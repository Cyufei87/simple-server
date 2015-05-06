from multiprocessing import Pool
import socket,select
import os,sys
import re
import logging
import mimetypes
import traceback
from logging.handlers import RotatingFileHandler

ilog = None

def init_log():
    global ilog
    ilog = logging.getLogger("socketserver")
    log_dir = "/var/log/socketserver"
    if not os.path.exists(log_dir):os.makedirs(log_dir)
    h1 = RotatingFileHandler(os.path.join(log_dir, "access.log"), maxBytes=5*1024*1024, backupCount=10)
    h2 = logging.StreamHandler(sys.stdout)
    f = logging.Formatter("%(asctime)s:%(levelname)s:%(message)s", "%Y-%m-%d %H:%M:%S")
    h1.setFormatter(f)
    h2.setFormatter(f)
    ilog.addHandler(h1)
    ilog.addHandler(h2)
    ilog.setLevel(logging.DEBUG)

SERVER = "Guess"
ENCODING = "utf8"

code_dict = {"200":"OK","404":"Not Found"}
def res_header(status_code,content_type,content_length):
    if status_code in code_dict:status_info = code_dict[status_code]
    else:status_info = "Error"
    header = "HTTP/1.1 %s %s\r\n"%(status_code, status_info)
    header += "Server: %s\r\n"%SERVER
    header += "Content-Type: %s\r\n"%content_type
    header += "Content-Length: %s\r\n"%content_length
    header += "\r\n"
    return header.encode(ENCODING)

def staticfile(addr, method, path, pid, req):
    path = "."+path
    if not os.path.exists(path):
        res = "404 Not Found".encode("utf8")
        return res_header("404", "text/plain", len(res))+res
    content_type = mimetypes.guess_type(path)[0] or "text/plain"
    f = open(path, "rb")
    data = f.read()
    f.close()
    content_length = len(data)
    return res_header("200", content_type, content_length)+data

def default(addr, method, path, pid, req):
    res = ""
    res += "Hello, %s:%s\n"%(addr[0], addr[1])
    res += "You are %sing %s"%(method, path)
    res += "\n\n"
    res += "Your header is:\n"
    res += req
    res += "                   Process %s"%pid
    res = res.encode(ENCODING)
    return res_header("200", "text/plain", len(res))+res

urls = [("^/favicon.ico$", staticfile), ("^/static/.*$", staticfile), ("^.*$",default)]

def handle_request(addr, req, pid):
    req = req.decode("utf8")
    headers = req.split("\t\n")
    tmp = headers[0].split()
    req_method = tmp[0]
    req_path = tmp[1]
    ilog.info("Process %s is handleing a request: %s:%s %s %s"%(pid, addr[0], addr[1], req_method, req_path))
    #print(req_path)
    res = b"error"
    for re_path,control in urls:
        if re.search(re_path, req_path) is not None:
            res = control(addr, req_method, req_path, pid, req)
            break
    return res

def worker(s):
    pid = os.getpid()
    try:
        while True:
            cs,addr = s.accept()
            try:
                #req = cs.recv(1024)
                req = b""
                while True:
                    #set timeout to 0.1s
                    r,w,e = select.select([cs],[],[],0.1)
                    if len(r)>0:
                        data = cs.recv(1024)
                        #in case client close the connect
                        if data==b"":break
                        req += data
                    else:break
                    #in case too big request
                    if len(req)>8*1024:break
                if len(req)>8*1024 or len(req)<8:continue
                #print(repr(req.decode("utf8")))
                res = handle_request(addr, req, pid)
                cs.send(res)
            except:
                error_info = traceback.format_exc()
                print(error_info)
                ilog.error(error_info)
            cs.close()
    except KeyboardInterrupt:pass

if __name__=="__main__":
    argv = sys.argv
    if len(argv)<2:
        print("usage:%s [port]"%argv[0])
        sys.exit(1)
    port = int(argv[1])
    
    s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("",port))
    s.listen(10)
    
    init_log()
    p = Pool(10)
    ilog.info("server running at %s.."%port)
    #p.map_async(worker, [s]*10)
    p.map(worker, [s]*10)
    print("exit..")
