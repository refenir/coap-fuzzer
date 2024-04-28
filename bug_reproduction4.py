from coapthon.client.helperclient import HelperClient
from coapthon.messages.request import Request
from coapthon import defines
from coapthon.serializer import Serializer
import subprocess
import socket
import random
from time import sleep
import traceback
#gdb -ex run -ex backtrace --args python2 coapserver.py -i 127.0.0.1 -p 5683 


def start_server():
    command = ["python2", "coapserver.py"]
    try:
        server_process = subprocess.Popen(command)
        print("CoAP server started")
        sleep(1)
        return server_process
    except Exception as e:
        print("Error restarting CoAP server", str(e))
        

class CoAPFuzzer:
    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    def send_requests(self):
        start_server()
        req = Request()
        serializer = Serializer()
        # sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        # check for timeout events        
        # generate random request
        req.type = random.choice([defines.Types["CON"], defines.Types["NON"], defines.Types["ACK"], defines.Types["RST"]])
        req.mid = random.randint(1, 65535) #required, don't change
        req.token = r"""+0j7502T@#\v3|? V2t%`auQ/=W	R	Qh;B#d/Dv@cfqI=
MiTci5<%>KYKz6XHOb982I=v}x@w7bg23y5<3UMvT2fXjXW )Apb"""
        req.destination = (self.host, self.port)
        req.code = random.choice([defines.Codes.GET.number, defines.Codes.POST.number, defines.Codes.PUT.number, defines.Codes.DELETE.number])
        req.uri_path = random.choice(["/basic/", "/storage/", "/separate/", "/long/", 
                                                "/big/", "/void/", "/xml/", "/encoding/", "/etag/", 
                                                "/child/", "/advanced/", "/advancedSeparate/", "/"])
        print(req.pretty_print())
        datagram = serializer.serialize(req) 
        self.sock.sendto(datagram, req.destination)
        
        datagram, source = self.sock.recvfrom(4096)
        
        received_message = serializer.deserialize(datagram, source) 
        # on response
        print(received_message.pretty_print())
        with open ("fuzzed requests.txt", "a") as f:
            f.write("Received:\n" + received_message.pretty_print())
            f.write("\n")
            
def main():
    host = "127.0.0.1" # "127.0.0.1"
    port = 5683
    fuzzer = CoAPFuzzer(host, port)
    fuzzer.send_requests()
    # fuzzer.close_connection()

if __name__ == "__main__":
    main()