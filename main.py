import requests, os, psutil, sys, jwt, pickle, json, binascii, time, urllib3, xKEys, base64, datetime, re, socket, threading
import asyncio
from protobuf_decoder.protobuf_decoder import Parser
from byte import *
from byte import xSEndMsg
from byte import Auth_Chat
from xHeaders import *
from datetime import datetime
from google.protobuf.timestamp_pb2 import Timestamp
from concurrent.futures import ThreadPoolExecutor
from threading import Thread
from flask import Flask, request, jsonify
from black9 import openroom, spmroom

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)  


connected_clients = {}
connected_clients_lock = threading.Lock()


active_spam_targets = {}
active_spam_lock = threading.Lock()


app = Flask(__name__)

class SimpleAPI:
    def __init__(self):
        self.running = True
        
    def process_spam_command(self, target_id, duration_minutes=None):
        try:
            if not ChEck_Commande(target_id):
                return {"status": "error", "message": " user_id غير صالح"}
                
            
            with active_spam_lock:
                if target_id not in active_spam_targets:
                    active_spam_targets[target_id] = {
                        'active': True,
                        'start_time': datetime.now(),
                        'duration': duration_minutes
                    }
                    threading.Thread(target=spam_worker, args=(target_id, duration_minutes), daemon=True).start()
                    message = f" تم بدء السبام على المستخدم: {target_id}"
                    if duration_minutes:
                        message += f" لمدة {duration_minutes} دقيقة"
                    return {"status": "success", "message": message}
                else:
                    return {"status": "error", "message": f" السبام يعمل بالفعل على المستخدم: {target_id}"}
                    
        except Exception as e:
            return {"status": "error", "message": f" خطأ في معالجة الأمر: {str(e)}"}
            
    def process_stop_command(self, target_id):
        try:
            with active_spam_lock:
                if target_id in active_spam_targets:
                    del active_spam_targets[target_id]
                    message = f" تم إيقاف السبام على المستخدم: {target_id}"
                    return {"status": "success", "message": message}
                else:
                    return {"status": "error", "message": f" لا يوجد سبام نشط على المستخدم: {target_id}"}
                    
        except Exception as e:
            return {"status": "error", "message": f" خطأ في معالجة الأمر: {str(e)}"}
            
    def get_status(self):
        try:
            with active_spam_lock:
                active_targets = list(active_spam_targets.keys())
                active_targets_info = []
                for target_id in active_targets:
                    info = active_spam_targets[target_id]
                    duration_info = ""
                    if info['duration']:
                        elapsed = datetime.now() - info['start_time']
                        remaining = info['duration'] * 9999 - elapsed.total_seconds()
                        if remaining > 0:
                            duration_info = f" ({int(remaining/9999)} دقيقة متبقية)"
                    active_targets_info.append(f"{target_id}{duration_info}")
                    
            with connected_clients_lock:
                accounts_count = len(connected_clients)
                accounts_list = list(connected_clients.keys())
                
            status_data = {
                "active_targets_count": len(active_targets),
                "active_targets": active_targets_info,
                "connected_accounts_count": accounts_count,
                "connected_accounts": accounts_list
            }
            
            return {"status": "success", "data": status_data}
            
        except Exception as e:
            return {"status": "error", "message": f" خطأ في الحصول على الحالة: {str(e)}"}

def spam_worker(target_id, duration_minutes=None):
    print(f" بدء السبام على الهدف: {target_id}" + (f" لمدة {duration_minutes} دقيقة" if duration_minutes else ""))
    
    start_time = datetime.now()
    
    while True:
        with active_spam_lock:
            if target_id not in active_spam_targets:
                print(f"️ توقف السبام على الهدف: {target_id}")
                break
                
            
            if duration_minutes:
                elapsed = datetime.now() - start_time
                if elapsed.total_seconds() >= duration_minutes * 9999:
                    print(f" انتهت مدة السبام على الهدف: {target_id}")
                    del active_spam_targets[target_id]
                    break
                
        try:
            send_spam_from_all_accounts(target_id)
            time.sleep(0.1)  
        except Exception as e:
            print(f" خطأ في السبام على {target_id}: {e}")
            time.sleep(1)

def send_spam_from_all_accounts(target_id):
    with connected_clients_lock:
        for account_id, client in connected_clients.items():
            try:
                if (hasattr(client, 'CliEnts2') and client.CliEnts2 and 
                    hasattr(client, 'key') and client.key and 
                    hasattr(client, 'iv') and client.iv):
                    
                    
                    try:
                        client.CliEnts2.send(openroom(client.key, client.iv))
                        print(f" فتح الروم من الحساب: {account_id}")
                    except Exception as e:
                        print(f" خطأ في فتح الروم من الحساب {account_id}: {e}")
                    
                    
                    for i in range(50):  
                        try:
                            client.CliEnts2.send(spmroom(client.key, client.iv, target_id))
                            print(f" إرسال سبام من الحساب {account_id} إلى {target_id} - المحاولة {i+1}")
                        except (BrokenPipeError, ConnectionResetError, OSError) as e:
                            print(f" خطأ اتصال للحساب {account_id}: {e}")
                            break
                        except Exception as e:
                            print(f" خطأ في الإرسال من الحساب {account_id}: {e}")
                            break
                else:
                    print(f" اتصال الحساب {account_id} غير نشط")
            except Exception as e:
                print(f" خطأ في إرسال السبام من الحساب {account_id}: {e}")


api = SimpleAPI()

@app.route('/spam', methods=['GET'])
def start_spam():
    target_id = request.args.get('user_id')
    duration = request.args.get('duration', type=int)
    
    if not target_id:
        return jsonify({"status": "error", "message": " يرجى إدخال الـ user_id"})
    
    result = api.process_spam_command(target_id, duration)
    return jsonify(result)

@app.route('/stop', methods=['GET'])
def stop_spam():
    target_id = request.args.get('user_id')
    
    if not target_id:
        return jsonify({"status": "error", "message": " يرجى إدخال الـ user_id"})
    
    result = api.process_stop_command(target_id)
    return jsonify(result)

@app.route('/status', methods=['GET'])
def get_status():
    result = api.get_status()
    return jsonify(result)

@app.route('/accounts', methods=['GET'])
def get_accounts():
    try:
        with connected_clients_lock:
            accounts_count = len(connected_clients)
            accounts_list = list(connected_clients.keys())
            
        accounts_data = {
            "connected_accounts_count": accounts_count,
            "connected_accounts": accounts_list
        }
        
        return jsonify({"status": "success", "data": accounts_data})
        
    except Exception as e:
        return jsonify({"status": "error", "message": f" خطأ في الحصول على الحسابات: {str(e)}"})

@app.route('/')
def home():
    
    return """
    <h1> نظام إدارة السبام (الإصدار المحدث)</h1>
    <p>Endpoints المتاحة:</p>
    <ul>
        <li><strong>بدء السبام:</strong> GET /spam?user_id=123456789&amp;duration=5 (duration اختياري - بالدقائق)</li>
        <li><strong>إيقاف السبام:</strong> GET /stop?user_id=123456789</li>
        <li><strong>حالة النظام:</strong> GET /status</li>
        <li><strong>الحسابات المتصلة:</strong> GET /accounts</li>
    </ul>
    <p><strong>ملاحظة:</strong> النظام المحدث يقوم بفتح روم أولاً ثم إرسال السبام عبر جميع الحسابات.</p>
    """

def run_api():
    print("🌐 بدء تشغيل API...")
    app.run(host='0.0.0.0', port=2315, debug=False)

def AuTo_ResTartinG():
    time.sleep(6 * 60 * 60)
    print('\n - AuTo ResTartinG The BoT ... ! ')
    p = psutil.Process(os.getpid())
    for handler in p.open_files():
        try:
            os.close(handler.fd)
        except Exception as e:
            print(f" - Error CLose Files : {e}")
    for conn in p.net_connections():
        try:
            if hasattr(conn, 'fd'):
                os.close(conn.fd)
        except Exception as e:
            print(f" - Error CLose Connection : {e}")
    sys.path.append(os.path.dirname(os.path.abspath(sys.argv[0])))
    python = sys.executable
    os.execl(python, python, *sys.argv)
       
def ResTarT_BoT():
    print('\n - ResTartinG The BoT ... ! ')
    p = psutil.Process(os.getpid())
    open_files = p.open_files()
    connections = p.net_connections()
    for handler in open_files:
        try:
            os.close(handler.fd)
        except Exception:
            pass           
    for conn in connections:
        try:
            conn.close()
        except Exception:
            pass
    sys.path.append(os.path.dirname(os.path.abspath(sys.argv[0])))
    python = sys.executable
    os.execl(python, python, *sys.argv)

def GeT_Time(timestamp):
    last_login = datetime.fromtimestamp(timestamp)
    now = datetime.now()
    diff = now - last_login   
    d = diff.days
    h , rem = divmod(diff.seconds, 3600)
    m , s = divmod(rem, 60)    
    return d, h, m, s

def Time_En_Ar(t): 
    return ' '.join(t.replace("Day","يوم").replace("Hour","ساعة").replace("Min","دقيقة").replace("Sec","ثانية").split(" - "))
    
Thread(target = AuTo_ResTartinG , daemon = True).start()


ACCOUNTS = []

def load_accounts_from_file(filename="accs.txt"):
    accounts = []
    try:
        with open(filename, "r", encoding="utf-8") as file:
            for line in file:
                line = line.strip()
                if line and not line.startswith("#"):  
                    
                    if ":" in line:
                        parts = line.split(":")
                        if len(parts) >= 2:
                            
                            account_id = parts[0].strip()
                            password = parts[1].strip()
                            accounts.append({'id': account_id, 'password': password})
                    else:
                        
                        accounts.append({'id': line.strip(), 'password': ''})
        print(f"تم تحميل {len(accounts)} حساب من {filename}")
    except FileNotFoundError:
        print(f"ملف {filename} غير موجود!")
    except Exception as e:
        print(f"حدث خطأ أثناء قراءة الملف: {e}")
    
    return accounts


ACCOUNTS = load_accounts_from_file()
            
class FF_CLient():

    def __init__(self, id, password):
        self.id = id
        self.password = password
        self.key = None
        self.iv = None
        self.Get_FiNal_ToKen_0115()     
            
    def Connect_SerVer_OnLine(self , Token , tok , host , port , key , iv , host2 , port2):
            try:
                self.AutH_ToKen_0115 = tok    
                self.CliEnts2 = socket.create_connection((host2 , int(port2)))
                self.CliEnts2.send(bytes.fromhex(self.AutH_ToKen_0115))                  
            except:pass        
            while True:
                try:
                    self.DaTa2 = self.CliEnts2.recv(99999)
                    if '0500' in self.DaTa2.hex()[0:4] and len(self.DaTa2.hex()) > 30:	         	    	    
                            self.packet = json.loads(DeCode_PackEt(f'08{self.DaTa2.hex().split("08", 1)[1]}'))
                            self.AutH = self.packet['5']['data']['7']['data']
                    
                except:pass    	
                                                            
    def Connect_SerVer(self , Token , tok , host , port , key , iv , host2 , port2):
            self.AutH_ToKen_0115 = tok    
            self.CliEnts = socket.create_connection((host , int(port)))
            self.CliEnts.send(bytes.fromhex(self.AutH_ToKen_0115))  
            self.DaTa = self.CliEnts.recv(1024)          	        
            threading.Thread(target=self.Connect_SerVer_OnLine, args=(Token , tok , host , port , key , iv , host2 , port2)).start()
            self.Exemple = xMsGFixinG('12345678')
            
            
            self.key = key
            self.iv = iv
            
            
            with connected_clients_lock:
                connected_clients[self.id] = self
                print(f" تم تسجيل الحساب {self.id} في القائمة العالمية، عدد الحسابات الآن: {len(connected_clients)}")
            
            while True:      
                try:
                    self.DaTa = self.CliEnts.recv(1024)   
                    if len(self.DaTa) == 0 or (hasattr(self, 'DaTa2') and len(self.DaTa2) == 0):	            		
                        try:            		    
                            self.CliEnts.close()
                            if hasattr(self, 'CliEnts2'):
                                self.CliEnts2.close()
                            self.Connect_SerVer(Token , tok , host , port , key , iv , host2 , port2)                    		                    
                        except:
                            try:
                                self.CliEnts.close()
                                if hasattr(self, 'CliEnts2'):
                                    self.CliEnts2.close()
                                self.Connect_SerVer(Token , tok , host , port , key , iv , host2 , port2)
                            except:
                                self.CliEnts.close()
                                if hasattr(self, 'CliEnts2'):
                                    self.CliEnts2.close()
                                ResTarT_BoT()	            
                                      
        	 	 
                                                               
                    if '/pp/' in self.input_msg[:4]:
                        self.target_id = self.input_msg[4:]	 
                        self.Zx = ChEck_Commande(self.target_id)
                        if True == self.Zx:	            		     
                            
                            threading.Thread(target=send_spam_from_all_accounts, args=(self.target_id,)).start()
                            time.sleep(2.5)    			         
                            self.CliEnts.send(xSEndMsg(f'\n[b][c][{ArA_CoLor()}] SuccEss Spam To {xMsGFixinG(self.target_id)} From All Accounts\n', 2 , self.DeCode_CliEnt_Uid , self.DeCode_CliEnt_Uid , key , iv))
                            time.sleep(1.3)
                            self.CliEnts.close()
                            if hasattr(self, 'CliEnts2'):
                                self.CliEnts2.close()
                            self.Connect_SerVer(Token , tok , host , port , key , iv , host2 , port2)	            		      	
                        elif False == self.Zx: 
                            self.CliEnts.send(xSEndMsg(f'\n[b][c][{ArA_CoLor()}] - PLease Use /pp/<id>\n - Ex : /pp/{self.Exemple}\n', 2 , self.DeCode_CliEnt_Uid , self.DeCode_CliEnt_Uid , key , iv))	
                            time.sleep(1.1)
                            self.CliEnts.close()
                            if hasattr(self, 'CliEnts2'):
                                self.CliEnts2.close()
                            self.Connect_SerVer(Token , tok , host , port , key , iv , host2 , port2)	            		

                except Exception as e:
                    print(f"Error in Connect_SerVer: {e}")
                    try:
                        self.CliEnts.close()
                        if hasattr(self, 'CliEnts2'):
                            self.CliEnts2.close()
                    except:
                        pass
                    self.Connect_SerVer(Token , tok , host , port , key , iv , host2 , port2)
                                    
    def GeT_Key_Iv(self , serialized_data):
        my_message = xKEys.MyMessage()
        my_message.ParseFromString(serialized_data)
        timestamp , key , iv = my_message.field21 , my_message.field22 , my_message.field23
        timestamp_obj = Timestamp()
        timestamp_obj.FromNanoseconds(timestamp)
        timestamp_seconds = timestamp_obj.seconds
        timestamp_nanos = timestamp_obj.nanos
        combined_timestamp = timestamp_seconds * 1_000_000_000 + timestamp_nanos
        return combined_timestamp , key , iv    

    def Guest_GeneRaTe(self , uid , password):
        self.url = "https://100067.connect.garena.com/oauth/guest/token/grant"
        self.headers = {"Host": "100067.connect.garena.com","User-Agent": "GarenaMSDK/4.0.19P4(G011A ;Android 9;en;US;)","Content-Type": "application/x-www-form-urlencoded","Accept-Encoding": "gzip, deflate, br","Connection": "close",}
        self.dataa = {"uid": f"{uid}","password": f"{password}","response_type": "token","client_type": "2","client_secret": "2ee44819e9b4598845141067b281621874d0d5d7af9d8f7e00c1e54715b7d1e3","client_id": "100067",}
        try:
            self.response = requests.post(self.url, headers=self.headers, data=self.dataa).json()
            self.Access_ToKen , self.Access_Uid = self.response['access_token'] , self.response['open_id']
            time.sleep(0.2)
            print(' - Starting ZIX OFFICIAL Freind BoT !')
            print(f' - Uid : {uid}\n - Password : {password}')
            print(f' - Access Token : {self.Access_ToKen}\n - Access Id : {self.Access_Uid}')
            return self.ToKen_GeneRaTe(self.Access_ToKen , self.Access_Uid)
        except Exception as e: 
            print(f"Error in Guest_GeneRaTe: {e}")
            time.sleep(10)
            return self.Guest_GeneRaTe(uid, password)
                                        
    def GeT_LoGin_PorTs(self , JwT_ToKen , PayLoad):
        self.UrL = 'https://clientbp.ggwhitehawk.com/GetLoginData'
        self.HeadErs = {
            'Expect': '100-continue',
            'Authorization': f'Bearer {JwT_ToKen}',
            'X-Unity-Version': '2022.3.47f1',
            'X-GA': 'v1 1',
            'ReleaseVersion': 'OB51',
            'Content-Type': 'application/x-www-form-urlencoded',
            'User-Agent': 'UnityPlayer/2022.3.47f1 (UnityWebRequest/1.0, libcurl/8.5.0-DEV)',
            'Host': 'clientbp.ggwhitehawk.com',
            'Connection': 'close',
            'Accept-Encoding': 'deflate, gzip',}        
        try:
                self.Res = requests.post(self.UrL , headers=self.HeadErs , data=PayLoad , verify=False)
                self.BesTo_data = json.loads(DeCode_PackEt(self.Res.content.hex()))  
                address , address2 = self.BesTo_data['32']['data'] , self.BesTo_data['14']['data'] 
                ip , ip2 = address[:len(address) - 6] , address2[:len(address) - 6]
                port , port2 = address[len(address) - 5:] , address2[len(address2) - 5:]             
                return ip , port , ip2 , port2          
        except requests.RequestException as e:
                print(f" - Bad Requests !")
        print(" - Failed To GeT PorTs !")
        return None, None, None, None
        
    def ToKen_GeneRaTe(self , Access_ToKen , Access_Uid):
        self.UrL = "https://loginbp.ggwhitehawk.com/MajorLogin"
        self.HeadErs = {
            'X-Unity-Version': '2022.3.47f1',
            'ReleaseVersion': 'OB51',
            'Content-Type': 'application/x-www-form-urlencoded',
            'X-GA': 'v1 1',
            'Content-Length': '928',
            'User-Agent': 'UnityPlayer/2022.3.47f1 (UnityWebRequest/1.0, libcurl/8.5.0-DEV)',
            'Host': 'loginbp.ggwhitehawk.com',
            'Connection': 'Keep-Alive',
            'Accept-Encoding': 'deflate, gzip'}   
        
        
        self.dT = bytes.fromhex('1a13323032352d31302d33312030353a31383a3235220966726565206669726528013a07312e3131382e344232416e64726f6964204f532039202f204150492d3238202850492f72656c2e636a772e32303232303531382e313134313333294a0848616e6468656c64520c4d544e2f537061636574656c5a045749464960800a68d00572033234307a2d7838362d3634205353453320535345342e3120535345342e32204156582041565832207c2032343030207c20348001e61e8a010f416472656e6f2028544d292036343092010d4f70656e474c20455320332e329a012b476f6f676c657c36323566373136662d393161372d343935622d396631362d303866653964336336353333a2010d3137362e32382e3133352e3233aa01026172b201203433303632343537393364653836646134323561353263616164663231656564ba010134c2010848616e6468656c64ca010d4f6e65506c7573204135303130ea014034653739616666653331343134393031353434656161626562633437303537333866653638336139326464346335656533646233333636326232653936363466f00101ca020c4d544e2f537061636574656cd2020457494649ca03203161633462383065636630343738613434323033626638666163363132306635e003b5ee02e803ff8502f003af13f803840780048c95028804b5ee0290048c95029804b5ee02b00404c80401d2043d2f646174612f6170702f636f6d2e6474732e667265656669726574682d66705843537068495636644b43376a4c2d574f7952413d3d2f6c69622f61726de00401ea045f65363261623933353464386662356662303831646233333861636233333439317c2f646174612f6170702f636f6d2e6474732e667265656669726574682d66705843537068495636644b43376a4c2d574f7952413d3d2f626173652e61706bf00406f804018a050233329a050a32303139313139303236a80503b205094f70656e474c455332b805ff01c00504e005c466ea05093372645f7061727479f80583e4068806019006019a060134a2060134b2062211541141595f58011f53594c59584056143a5f535a525c6b5c04096e595c3b000e61')
        
       
        self.dT = self.dT.replace(b'2025-07-30 14:11:20' , str(datetime.now())[:-7].encode())        
        self.dT = self.dT.replace(b'4e79affe31414901544eaabebc4705738fe683a92dd4c5ee3db33662b2e9664f' , Access_ToKen.encode())
        self.dT = self.dT.replace(b'4306245793de86da425a52caadf21eed' , Access_Uid.encode())
        
        try:
            
            hex_data = self.dT.hex()
            encoded_data = EnC_AEs(hex_data)
            
            
            if not all(c in '0123456789abcdefABCDEF' for c in encoded_data):
                print(" Invalid hex output from EnC_AEs, using alternative encoding")
                
                encoded_data = hex_data  
            
            self.PaYload = bytes.fromhex(encoded_data)
        except Exception as e:
            print(f" Error in encoding: {e}")
            
            self.PaYload = self.dT
        
        self.ResPonse = requests.post(self.UrL, headers = self.HeadErs ,  data = self.PaYload , verify=False)        
        if self.ResPonse.status_code == 200 and len(self.ResPonse.text) > 10:
            try:
                self.BesTo_data = json.loads(DeCode_PackEt(self.ResPonse.content.hex()))
                self.JwT_ToKen = self.BesTo_data['8']['data']           
                self.combined_timestamp , self.key , self.iv = self.GeT_Key_Iv(self.ResPonse.content)
                ip , port , ip2 , port2 = self.GeT_LoGin_PorTs(self.JwT_ToKen , self.PaYload)            
                return self.JwT_ToKen , self.key , self.iv, self.combined_timestamp , ip , port , ip2 , port2
            except Exception as e:
                print(f" Error parsing response: {e}")
                time.sleep(5)
                return self.ToKen_GeneRaTe(Access_ToKen, Access_Uid)
        else:
            print(f" Error in ToKen_GeneRaTe, status: {self.ResPonse.status_code}")
            time.sleep(5)
            return self.ToKen_GeneRaTe(Access_ToKen, Access_Uid)
      
    def Get_FiNal_ToKen_0115(self):
        try:
            result = self.Guest_GeneRaTe(self.id , self.password)
            if not result:
                print(" Failed to get tokens, retrying...")
                time.sleep(5)
                return self.Get_FiNal_ToKen_0115()
                
            token , key , iv , Timestamp , ip , port , ip2 , port2 = result
            
            if not all([ip, port, ip2, port2]):
                print(" Failed to get ports, retrying...")
                time.sleep(5)
                return self.Get_FiNal_ToKen_0115()
                
            self.JwT_ToKen = token        
            try:
                self.AfTer_DeC_JwT = jwt.decode(token, options={"verify_signature": False})
                self.AccounT_Uid = self.AfTer_DeC_JwT.get('account_id')
                self.EncoDed_AccounT = hex(self.AccounT_Uid)[2:]
                self.HeX_VaLue = DecodE_HeX(Timestamp)
                self.TimE_HEx = self.HeX_VaLue
                self.JwT_ToKen_ = token.encode().hex()
                print(f' ProxCed Uid : {self.AccounT_Uid}')
            except Exception as e:
                print(f" Error In ToKen : {e}")
                time.sleep(5)
                return self.Get_FiNal_ToKen_0115()
                
            try:
                self.Header = hex(len(EnC_PacKeT(self.JwT_ToKen_, key, iv)) // 2)[2:]
                length = len(self.EncoDed_AccounT)
                self.__ = '00000000'
                if length == 9: self.__ = '0000000'
                elif length == 8: self.__ = '00000000'
                elif length == 10: self.__ = '000000'
                elif length == 7: self.__ = '000000000'
                else:
                    print('Unexpected length encountered')                
                self.Header = f'0115{self.__}{self.EncoDed_AccounT}{self.TimE_HEx}00000{self.Header}'
                self.FiNal_ToKen_0115 = self.Header + EnC_PacKeT(self.JwT_ToKen_ , key , iv)
            except Exception as e:
                print(f" Error In Final Token : {e}")
                time.sleep(5)
                return self.Get_FiNal_ToKen_0115()
                
            self.AutH_ToKen = self.FiNal_ToKen_0115
            self.Connect_SerVer(self.JwT_ToKen , self.AutH_ToKen , ip , port , key , iv , ip2 , port2)        
            return self.AutH_ToKen , key , iv
            
        except Exception as e:
            print(f" Error in Get_FiNal_ToKen_0115: {e}")
            time.sleep(10)
            return self.Get_FiNal_ToKen_0115()

def start_account(account):
    try:
        print(f" Starting account: {account['id']}")
        FF_CLient(account['id'], account['password'])
    except Exception as e:
        print(f" Error starting account {account['id']}: {e}")
        time.sleep(5)
        start_account(account)  

def StarT_SerVer():
    api_thread = threading.Thread(target=run_api, daemon=True)
    api_thread.start()
    
    threads = []
    
    for account in ACCOUNTS:
        thread = threading.Thread(target=start_account, args=(account,))
        thread.daemon = True
        threads.append(thread)
        thread.start()
        time.sleep(3)  
    
    
    for thread in threads:
        thread.join()
  
StarT_SerVer()
