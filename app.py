from flask import Flask, request, jsonify
from datetime import datetime
import requests
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import urllib3
import threading
import queue
import time
from functools import wraps
import logging
from werkzeug.serving import WSGIRequestHandler

# Configuration
MAX_WORKERS = 50  # Number of concurrent workers
REQUEST_TIMEOUT = 10  # Seconds to wait for API responses
RATE_LIMIT_WINDOW = 60  # Seconds for rate limiting window
RATE_LIMIT_MAX = 100  # Max requests per window per client

# Setup
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
app = Flask(__name__)
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Worker pool for concurrent processing
task_queue = queue.Queue()
result_cache = {}  # Simple cache for frequent requests
cache_lock = threading.Lock()

# Constants for encryption
ENCRYPTION_KEY = bytes([89, 103, 38, 116, 99, 37, 68, 69, 117, 104, 54, 37, 90, 99, 94, 56])
ENCRYPTION_IV = bytes([54, 111, 121, 90, 68, 114, 50, 50, 69, 51, 121, 99, 104, 106, 77, 37])
TEMPLATE_DATA = bytes.fromhex('1a13323032352d31312d32362030313a35313a3238220966726565206669726528013a07312e3132302e314232416e64726f6964204f532039202f204150492d3238202850492f72656c2e636a772e32303232303531382e313134313333294a0848616e6468656c64520c4d544e2f537061636574656c5a045749464960800a68d00572033234307a2d7838362d3634205353453320535345342e3120535345342e32204156582041565832207c2032343030207c20348001e61e8a010f416472656e6f2028544d292036343092010d4f70656e474c20455320332e329a012b476f6f676c657c36323566373136662d393161372d343935622d396631362d303866653964336336353333a2010e3137362e32382e3133392e313835aa01026172b201203433303632343537393364653836646134323561353263616164663231656564ba010134c2010848616e6468656c64ca010d4f6e65506c7573204135303130ea014063363961653230386661643732373338623637346232383437623530613361316466613235643161313966616537343566633736616334613065343134633934f00101ca020c4d544e2f537061636574656cd2020457494649ca03203161633462383065636630343738613434323033626638666163363132306635e003b5ee02e8039a8002f003af13f80384078004a78f028804b5ee029004a78f029804b5ee02b00404c80401d2043d2f646174612f6170702f636f6d2e6474732e667265656669726574682d66705843537068495636644b43376a4c2d574f7952413d3d2f6c69622f61726de00401ea045f65363261623933353464386662356662303831646233333861636233333439317c2f646174612f6170702f636f6d2e6474732e667265656669726574682d66705843537068495636644b43376a4c2d574f7952413d3d2f626173652e61706bf00406f804018a050233329a050a32303139313139303236a80503b205094f70656e474c455332b805ff01c00504e005be7eea05093372645f7061727479f205704b717348543857393347646347335a6f7a454e6646775648746d377171316552554e6149444e67526f626f7a4942744c4f695943633459367a767670634943787a514632734f453463627974774c7334785a62526e70524d706d5752514b6d654f35766373386e51594268777148374bf805e7e4068806019006019a060134a2060134b2062213521146500e590349510e460900115843395f005b510f685b560a6107576d0f0366')

# Rate limiting
request_counts = {}
last_reset_time = time.time()

def reset_rate_limits():
    global last_reset_time, request_counts
    current_time = time.time()
    if current_time - last_reset_time > RATE_LIMIT_WINDOW:
        request_counts = {}
        last_reset_time = current_time
    threading.Timer(RATE_LIMIT_WINDOW, reset_rate_limits).start()

reset_rate_limits()  # Start the rate limit reset timer

def rate_limited(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        client_ip = request.remote_addr
        reset_rate_limits()  # Ensure timer is running
        
        with cache_lock:
            request_counts[client_ip] = request_counts.get(client_ip, 0) + 1
            if request_counts[client_ip] > RATE_LIMIT_MAX:
                return jsonify({
                    "status": "error",
                    "message": "Rate limit exceeded. Please try again later."
                }), 429
        return f(*args, **kwargs)
    return decorated_function

def encrypt_api(plain_text):
    try:
        plain_text = bytes.fromhex(plain_text)
        cipher = AES.new(ENCRYPTION_KEY, AES.MODE_CBC, ENCRYPTION_IV)
        cipher_text = cipher.encrypt(pad(plain_text, AES.block_size))
        return cipher_text.hex()
    except Exception as e:
        logger.error(f"Encryption error: {str(e)}")
        raise

def worker():
    while True:
        try:
            task = task_queue.get()
            if task is None:
                break
            uid, password, callback = task
            try:
                result = generate_token(uid, password)
                callback(result)
            except Exception as e:
                logger.error(f"Worker error for UID {uid}: {str(e)}")
                callback({"status": "error", "message": str(e)})
            finally:
                task_queue.task_done()
        except Exception as e:
            logger.error(f"Worker thread error: {str(e)}")

# Start worker threads
for i in range(MAX_WORKERS):
    t = threading.Thread(target=worker)
    t.daemon = True
    t.start()

def generate_token(uid, password):
    cache_key = f"{uid}:{password}"
    
    # Check cache first
    with cache_lock:
        if cache_key in result_cache:
            return result_cache[cache_key]
    
    # Get initial token from Garena
    url = "https://100067.connect.garena.com/oauth/guest/token/grant"
    headers = {
        "Host": "100067.connect.garena.com",
        "User-Agent": "GarenaMSDK/4.0.19P4(G011A ;Android 9;en;US;)",
        "Content-Type": "application/x-www-form-urlencoded",
        "Accept-Encoding": "gzip, deflate, br",
        "Connection": "close",
    }
    data = {
        "uid": uid,
        "password": password,
        "response_type": "token",
        "client_type": "2",
        "client_secret": "",
        "client_id": "100067",
    }
    
    try:
        response = requests.post(url, headers=headers, data=data, timeout=REQUEST_TIMEOUT)
        response.raise_for_status()
        data = response.json()
        
        if "access_token" not in data or "open_id" not in data:
            error_msg = f"Missing keys in Garena response: {data}"
            logger.error(error_msg)
            return {"status": "error", "message": error_msg}
        
        # Process the token
        NEW_ACCESS_TOKEN = data['access_token']
        NEW_OPEN_ID = data['open_id']
        OLD_ACCESS_TOKEN = "c69ae208fad72738b674b2847b50a3a1dfa25d1a19fae745fc76ac4a0e414c94"
        OLD_OPEN_ID = "4306245793de86da425a52caadf21eed"
        
        # Prepare the payload
        modified_data = TEMPLATE_DATA.replace(OLD_OPEN_ID.encode(), NEW_OPEN_ID.encode())
        modified_data = modified_data.replace(OLD_ACCESS_TOKEN.encode(), NEW_ACCESS_TOKEN.encode())
        encrypted_payload = encrypt_api(modified_data.hex())
        
        # Make the final request
        headers = {
            'X-Unity-Version': '2018.4.11f1',
            'ReleaseVersion': 'OB52',
            'Content-Type': 'application/x-www-form-urlencoded',
            'X-GA': 'v1 1',
            'Authorization': 'Bearer eyJhbGciOiJIUzI1NiIsInN2ciI6IjEiLCJ0eXAiOiJKV1QifQ.eyJhY2NvdW50X2lkIjo5MjgwODkyMDE4LCJuaWNrbmFtZSI6IkJZVEV2R3QwIiwibm90aV9yZWdpb24iOiJNRSIsImxvY2tfcmVnaW9uIjoiTUUiLCJleHRlcm5hbF9pZCI6ImYzNGQyMjg0ZWJkYmFkNTkzNWJjOGI1NTZjMjY0ZmMwIiwiZXh0ZXJuYWxfdHlwZSI6NCwicGxhdF9pZCI6MCwiY2xpZW50X3ZlcnNpb24iOiIxLjEwNS41IiwiZW11bGF0b3Jfc2NvcmUiOjAsImlzX2VtdWxhdG9yIjpmYWxzZSwiY291bnRyeV9jb2RlIjoiRUciLCJleHRlcm5hbF91aWQiOjMyMzQ1NDE1OTEsInJlZ19hdmF0YXIiOjEwMjAwMDAwNSwic291cmNlIjoyLCJsb2NrX3JlZ2lvbl90aW1lIjoxNzE0NjYyMzcyLCJjbGllbnRfdHlwZSI6MSwic2lnbmF0dXJlX21kNSI6IiIsInVzaW5nX3ZlcnNpb24iOjEsInJlbGVhc2VfY2hhbm5lbCI6ImlvcyIsInJlbGVhc2VfdmVyc2lvbiI6Ik9CNDUiLCJleHAiOjE3MjIwNTkxMjF9.yYQZX0GeBMeBtMLhyCjSV0Q3e0jAqhnMZd3XOs6Ldk4',
            'Content-Length': '928',
            'User-Agent': 'Dalvik/2.1.0 (Linux; U; Android 7.1.2; ASUS_Z01QD Build/QKQ1.190825.002)',
            'Host': 'loginbp.ggpolarbear.com',
            'Connection': 'Keep-Alive',
            'Accept-Encoding': 'gzip'
        }
        
        response = requests.post(
            "https://loginbp.ggpolarbear.com/MajorLogin",
            headers=headers,
            data=bytes.fromhex(encrypted_payload),
            verify=False,
            timeout=REQUEST_TIMEOUT
        )
        response.raise_for_status()
        
        if len(response.text) < 10:
            error_msg = "Invalid response from MajorLogin"
            logger.error(error_msg)
            return {"status": "error", "message": error_msg}
        
        # Extract the JWT token
        BASE64_TOKEN = response.text[response.text.find("eyJhbGciOiJIUzI1NiIsInN2ciI6IjEiLCJ0eXAiOiJKV1QifQ"):-1]
        second_dot_index = BASE64_TOKEN.find(".", BASE64_TOKEN.find(".") + 1)
        BASE64_TOKEN = BASE64_TOKEN[:second_dot_index + 44]
        
        result = {"status": "success", "token": BASE64_TOKEN}
        
        # Cache the result
        with cache_lock:
            result_cache[cache_key] = result
            # Simple cache eviction when it gets too big
            if len(result_cache) > 1000:
                result_cache.clear()
        
        return result
        
    except requests.exceptions.RequestException as e:
        error_msg = f"Request error: {str(e)}"
        logger.error(error_msg)
        return {"status": "error", "message": error_msg}
    except Exception as e:
        error_msg = f"Unexpected error: {str(e)}"
        logger.error(error_msg)
        return {"status": "error", "message": error_msg}

@app.route('/get', methods=['GET'])
@rate_limited
def check_token():
    uid = request.args.get('uid')
    password = request.args.get('password')
    
    if not uid or not password:
        return jsonify({
            "status": "error",
            "message": "Both uid and password parameters are required"
        }), 400
    
    # Use a queue to get the result asynchronously
    result_queue = queue.Queue()
    
    def callback(result):
        result_queue.put(result)
    
    task_queue.put((uid, password, callback))
    
    try:
        result = result_queue.get(timeout=REQUEST_TIMEOUT)
        return jsonify(result)
    except queue.Empty:
        return jsonify({
            "status": "error",
            "message": "Request timed out"
        }), 504

if __name__ == '__main__':
    # Configure Flask for production
    WSGIRequestHandler.protocol_version = "HTTP/1.1"
    app.run(host='0.0.0.0', port=8792, threaded=True)