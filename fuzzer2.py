import os
import signal
from coapthon.client.helperclient import HelperClient
from coapthon.messages.request import Request
from coapthon import defines
from coapthon.serializer import Serializer
import subprocess
import socket
import random
import unicodedata
from time import sleep
from time import time
import traceback
#gdb -ex run -ex backtrace --args python2 coapserver.py -i 127.0.0.1 -p 5683 

timeout = time() + 60

def start_server():
    command = ["python2", "coapserver.py"]
    try:
        with open("server_output.txt", "a") as out_file, open("server_error.txt", "a") as err_file:
            server_process = subprocess.Popen(command, stdout=out_file, stderr=err_file)
        print("CoAP server started")
        return server_process
    except Exception as e:
        print("Error restarting CoAP server", str(e))
        

class CoAPFuzzer:
    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        # self.client = HelperClient(server=(self.host, self.port), sock=self.sock)
        self.seed_queue = [
            {
                "token":"toke", "payload":"THE QUICK BROWN FOX JUMPED OVER THE LAZY DOG'S BACK 1234567890"
            },
            {
                "token":"hahaadfafadfasdfasdfasdfadfadfafadfadfas", "payload":"Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum."
            }
            ]
        self.failure_queue = []
        self.timeout_count = 0

    def fuzz_and_send_requests(self, num_requests, num_bytes):
        server_process = start_server()
        while True:
            print("START")
            
            try:
                sleep(0.5)
                req = Request()
                serializer = Serializer()
                # sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                # check for timeout events
                self.sock.settimeout(5)
                seed = random.choice(self.seed_queue)
                
                # generate random request
                req.type = random.choice([defines.Types["CON"], defines.Types["NON"], defines.Types["ACK"], defines.Types["RST"]])
                req.mid = random.randint(1, 65535) #required, don't change
                req.token = self.mutate_input(seed["token"], "token") # If string is 100 letters long, the server will crash
                #req.options = s
                req.payload = self.mutate_input(seed["payload"], "payload")
                req.destination = (self.host, self.port)
                req.code = random.choice([defines.Codes.GET.number, defines.Codes.POST.number, defines.Codes.PUT.number, defines.Codes.DELETE.number]) # Everytime EMPTY is chosen, the server will give up, but not crash
                req.uri_path = random.choice(["/basic/", "/storage/", "/separate/", "/long/", "/big/", "/void/", "/xml/", "/encoding/", "/etag/", "/child/", "/advanced/", "/advancedSeparate/", "/"])
                req.accept = random.choice([defines.Content_types["text/plain"], defines.Content_types["application/link-format"], defines.Content_types["application/xml"], defines.Content_types["application/octet-stream"], defines.Content_types["application/exi"], defines.Content_types["application/json"]])
            
                # add discovery/observe mutation if the request is a GET request
                if req.code == defines.Codes.GET.number:
                    mutate_obs_disc = random.random()
                    if mutate_obs_disc < 0.33:
                        req.observe = random.randint(0, 1)
                    elif mutate_obs_disc < 0.66:
                        del req.uri_path
                        req.uri_path = defines.DISCOVERY_URL
                # print(req.pretty_print())
                # with open ("fuzzed requests.txt", "a") as f:
                #     f.write("Request:\n" + req.pretty_print())
                #     f.write("\n")
                
                datagram = serializer.serialize(req) 
                self.sock.sendto(datagram, req.destination)
                
                datagram, source = self.sock.recvfrom(4096)
                
                received_message = serializer.deserialize(datagram, source) 
                # on response
                print(received_message.pretty_print())
                with open ("fuzzed requests.txt", "a") as f:
                    f.write("Received:\n" + received_message.pretty_print())
                    f.write("\n")
                
            except Exception as e:
                print("exception:", e)
                traceback.print_exc()
                server_process = start_server()
                with open ("crashed_log.txt", "a") as f:
                    f.write("Request:\n" + req.pretty_print())
                    f.write("\n")
                sleep(1)
                
            print("end")
            

    # def close_connection(self):
    #     self.client.stop()
    
    def mutate_input(self, input_data, key):
        mutations = ("bitflip", "byteflip", "arith inc/dec", "interesting values", "user extras", "auto extras", "random bytes", "delete bytes", "insert bytes", "overwrite bytes", "cross over")
        mutation_chose = mutations[random.randint(0,len(mutations)-1)]
        mutated_data = self.apply_mutation(input_data, mutation_chose, key)
        return mutated_data
    
    

    def apply_mutation(self, data, mutation, key):
        mutated_input = bytearray()
        mutated_input.extend(data.encode("ascii"))
        if mutation == "bitflip":
            n = random.choice((1,2,4))
            for i in range(0, len(mutated_input)*8, 1):
                byte_index = i // 8
                bit_index = i % 8
                for _ in range(n):
                    if i < len(mutated_input)*8:
                        mutated_input[byte_index] ^= (1 << (bit_index))
        elif mutation == "byteflip":
            n = random.choice((1,2,4))
            for i in range(0, len(mutated_input), 1):
                for j in range(n):
                    if (i+j) < len(mutated_input):
                        mutated_input[i+j] ^= 0xFF
        elif mutation == "arith inc/dec":
            n = random.choice((1,2,4))
            operator = random.choice((1, -1))
            for i in range(0, len(mutated_input), 1):
                for j in range(n):
                    if (i+j) < len(mutated_input):
                        mutated_input[i+j] = (mutated_input[i+j] + operator) % 256
        elif mutation == "interesting values":
            interesting_values = (0x00, 0xFF, 0x7F, 0x80, 0x01, 0x7E, 0x7D, 0x7C, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F)
            n = random.choice((1,2,4))
            for i in range(0, len(mutated_input), 1):
                for j in range(n):
                    if (i+j) < len(mutated_input):
                        mutated_input[i+j] = random.choice(interesting_values)
        elif mutation == "random bytes":
            byte_index = random.randint(0, len(mutated_input)-1)
            mutated_input[byte_index] = random.randint(0, 255)
        elif mutation == "delete bytes":
            size = random.randint(1, 4)
            start = random.randint(0, len(mutated_input))
            del mutated_input[start:start+size]
        elif mutation == "insert bytes":
            size = random.randint(1, 4)
            start = random.randint(0, len(mutated_input))
            mutated_input[start:start] = bytearray(random.sample(range(256), k=size))
        elif mutation == "overwrite bytes":
            size = random.randint(1, 4)
            start = random.randint(0, len(mutated_input))
            mutated_input[start:start+size] = bytearray(random.sample(range(256), k=size))
        elif mutation == "cross over":
            data2 = random.choice(self.seed_queue)
            other_data = bytearray()
            other_data.extend(data2[key].encode("ascii"))
            if len(other_data) < len(mutated_input):
                splice_loc = random.randint(0, len(other_data))
            else:
                splice_loc = random.randint(0, len(mutated_input))
            mutated_input[splice_loc:] = other_data[splice_loc:]
        # try:
        #     mutated_input = bytes(mutated_input).decode("utf-8")
        # except UnicodeDecodeError:
        #     mutated_input =bytes(mutated_input).decode("utf-8", errors="replace")
        mutated_input = unicodedata.normalize("NFKD", bytes(mutated_input).decode("ascii", errors="ignore"))
        print(mutated_input)
        return mutated_input
    
    def choose_next(self):
        return random.choice(self.seed_queue)
    
    def is_interesting(self, request, response):

        pass

    
def main():
    host = "127.0.0.1" # "127.0.0.1"
    port = 5683
    fuzzer = CoAPFuzzer(host, port)
    fuzzer.fuzz_and_send_requests(num_requests=3, num_bytes=5)
    # fuzzer.close_connection()

if __name__ == "__main__":
    main()