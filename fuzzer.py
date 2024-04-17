from coapthon.client.helperclient import HelperClient
from coapthon.messages.request import Request
from coapthon import defines
from coapthon.serializer import Serializer
import subprocess
import socket
import random
import os
import json
import signal
import string
import unicodedata
from time import sleep
from time import time
import coverage
#gdb -ex run -ex backtrace --args python2 coapserver.py -i 127.0.0.1 -p 5683 

# import codecs
# codecs.register(lambda name: codecs.lookup('utf-8') if name == 'cp65001' else None)
pheromone_decrease = -1
pheromone_increase = 10
test_count = 0
unique_bugs = 0

def restart_server(p):
    os.killpg(os.getpgid(p.pid), signal.SIGTERM)
    command = ["python2", "coapserver.py"]
    try:
        # p = subprocess.Popen(command, preexec_fn=os.setsid)
        with open("server_output.txt", "a") as out_file, open("server_error.txt", "a") as err_file:
                p = subprocess.Popen(command, 
                                    #  shell=True, # windows
                                    #  creationflags=subprocess.CREATE_NEW_PROCESS_GROUP,  # windows
                                    preexec_fn=os.setsid, # unix
                                    stdout=out_file, 
                                    stderr=err_file)
        print("CoAP server restarted")
        return p
    except Exception as e:
        print("Error restarting CoAP server", str(e))

class CoAPFuzzer:
    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.client = HelperClient(server=(self.host, self.port))
        self.coverage_before = None
        self.seed_queue = []
        self.failure_queue = []

    def fuzz_and_send_requests(self):
        global pheromone_decrease, pheromone_increase
        with open("seed.json", "r") as f:
            self.seed_queue = json.load(f)
        command = ["python2", "coapserver.py"]
        try:
            with open("server_output.txt", "a") as out_file, open("server_error.txt", "a") as err_file:
                p = subprocess.Popen(command, 
                                    #  shell=True, # windows
                                    #  creationflags=subprocess.CREATE_NEW_PROCESS_GROUP,  # windows
                                    preexec_fn=os.setsid, # unix
                                    stdout=out_file, 
                                    stderr=err_file)
            print("CoAP server started")
        except Exception as e:
            print("Error starting CoAP server", str(e))
        sleep(1)
        while True:
            seed = self.choose_next()
            print(seed)
            energy = self.assign_energy(seed)
            if seed["pheromone"] > 2:
                seed["pheromone"] += pheromone_decrease
            serializer = Serializer()
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            # check for timeout events
            sock.settimeout(2)
            # generate random request
            for i in range(energy):
                req = Request()
                req.type = random.choice([defines.Types["CON"], defines.Types["NON"], 
                                          defines.Types["ACK"], defines.Types["RST"]])
                req.mid = random.randint(1, 65535) #required, don't change
                # If string is 100 letters long, the server will crash
                req.token = self.mutate_input(seed["token"], "token") 
                req.payload = self.mutate_input(seed["payload"], "payload")
                req.destination = (self.host, self.port)
                req.code = random.choice([defines.Codes.GET.number, defines.Codes.POST.number, 
                                          defines.Codes.PUT.number, defines.Codes.DELETE.number]) 
                req.uri_path = random.choice(["/basic/", "/storage/", "/separate/", "/long/", 
                                              "/big/", "/void/", "/xml/", "/encoding/", "/etag/", 
                                              "/child/", "/advanced/", "/advancedSeparate/", "/"])
                mutated_seed = {"token":req.token, "payload":req.payload, "count":0, "pheromone":10}

                # add discovery/observe mutation if the request is a GET request
                if req.code == defines.Codes.GET.number:
                    mutate_obs_disc = random.random()
                    if mutate_obs_disc < 0.33:
                        req.observe = random.randint(0, 1)
                    elif mutate_obs_disc < 0.66:
                        del req.uri_path
                        req.uri_path = defines.DISCOVERY_URL
                print(req.pretty_print())

                # send request
                datagram = serializer.serialize(req) 
                sock.sendto(datagram, req.destination)
                # try to receive response
                try:
                    datagram, source = sock.recvfrom(4096)
                # handle timeouts (server crash / no response)
                except socket.timeout:
                    seed["pheromone"] += pheromone_increase
                    print("Timeout")
                    print("Server crashed. Restarting")
                    with open("crashed_log.txt", "a") as f:
                        f.write("Request:\n" + req.pretty_print())
                        f.write("\n")
                    p = restart_server(p)
                    sleep(1)
                    continue
                received_message = serializer.deserialize(datagram, source) # response
                print(received_message.pretty_print())
                if self.is_interesting():
                    self.seed_queue.append(mutated_seed)

    def close_connection(self):
        self.client.stop()
    
    def mutate_input(self, input_data, key):
        mutations = ("bitflip", "byteflip", "arith inc/dec", "interesting values", 
                     "random bytes", "delete bytes", "insert bytes", "overwrite bytes", 
                     "cross over")
        mutation_chose = mutations[random.randint(0,len(mutations)-1)]
        mutated_data = self.apply_mutation(input_data, mutation_chose, key)
        return mutated_data
    

    def apply_mutation(self, data, mutation, key):
        if data == "" or data is None:
            if key == "token":
                data = ''.join(random.choice(string.printable) for i in range(100)) 
            elif key == "payload":
                data = ''.join(random.choice(string.printable) for i in range(1000))
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
        if mutated_input == "" or mutated_input is None:
            if key == "token":
                mutated_input = ''.join(random.choice(string.printable) for i in range(100)) 
            elif key == "payload":
                mutated_input = ''.join(random.choice(string.printable) for i in range(1000))
        return mutated_input
    
    def choose_next(self):
        if len(self.seed_queue) != 0:
            self.seed_queue.sort(key=lambda x: x["count"])
            self.seed_queue[0]["count"] += 1
            return self.seed_queue[0]
        return "Seed queue is empty"
    
    def is_interesting(self):
        if self.coverage_before is None:
            self.coverage_before = subprocess.check_output(["coverage", "report", "-m"]).decode()
            return True

        # Get the new coverage data
        coverage_after  = subprocess.check_output(["coverage", "report", "-m"]).decode()
        # Check if coverage has increased
        if self.coverage_before != coverage_after:
            return True
        return False
    
    def assign_energy(self, seed):
        # ant colony optimisation
        return seed["pheromone"]

    
    def signal_handler(self, sig, frame):
        subprocess.Popen(["coverage", "report", "-m"])
        subprocess.Popen(["coverage", "html"])
        #with open("seed.json", "w") as f:
            #json.dump(self.seed_queue, f)
        print("Exiting...")
        exit(0)    

    
def main():
    host = "127.0.0.1"
    port = 5683
    fuzzer = CoAPFuzzer(host, port)
    signal.signal(signal.SIGINT, fuzzer.signal_handler)
    # while(1):
    #     try:
    fuzzer.fuzz_and_send_requests()
        # except:
    fuzzer.close_connection()

if __name__ == "__main__":
    main()