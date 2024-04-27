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
import sys
import unicodedata
from datetime import datetime
from time import sleep
from time import time
import csv
from coverage import Coverage
import threading

# import codecs
# codecs.register(lambda name: codecs.lookup('utf-8') if name == 'cp65001' else None)
pheromone_decrease = -1
pheromone_increase = 10
test_count = 0
unique_bugs = []
ascii_error_found = False

def start_server():
    # if p is not None:
    #     os.killpg(os.getpgid(p.pid), signal.SIGTERM)  # unix
    #     # os.kill(p.pid, signal.CTRL_C_EVENT)  # windows
    command = ["python2", "coapserver.py"]
    try:
        # p = subprocess.Popen(command, preexec_fn=os.setsid)
        with open("server_output.txt", "a") as out_file:
                p = subprocess.Popen(command, 
                                    #creationflags=subprocess.CREATE_NEW_PROCESS_GROUP,  # windows
                                    preexec_fn=os.setsid, # unix
                                    stdout=out_file, 
                                    stderr=subprocess.PIPE)
        
        print("CoAP server started")
        sleep(1)
        return p
    except Exception as e:
        print("Error restarting CoAP server", str(e))
        return None

def handle_errors(p):
    while True:
        line = p.stderr.read()
        if line == '' and p.poll() is not None:
            break
        if line:
            error = line
            if error and error not in unique_bugs:
                unique_bugs.append(error)
                print("New unique error detected:"), error
            elif error:
                print("Repeated error:"), error
            return
        sleep(0.1)

class CoAPFuzzer:
    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.client = HelperClient(server=(self.host, self.port))
        self.coverage_before = None
        self.seed_queue = []
        self.failure_queue = []
        self.coverage = Coverage()

    def fuzz_and_send_requests(self):
        global pheromone_decrease, pheromone_increase, ascii_error_found
        with open("seed.json", "r") as f:
            self.seed_queue = json.load(f)
        p = start_server()
        with open ('RQ/RQ1_1.csv', 'wb') as rq1_1_csv, open('RQ/RQ1_2.csv', 'wb') as rq1_2_csv, open ('RQ/RQ1_3.csv', 'wb') as rq1_3_csv, open ('RQ/RQ2.csv', 'wb') as rq2_csv:
            writer1_1 = csv.writer(rq1_1_csv, delimiter=',', quotechar='"', quoting=csv.QUOTE_MINIMAL)
            writer1_2 = csv.writer(rq1_2_csv, delimiter=',', quotechar='"', quoting=csv.QUOTE_MINIMAL)
            writer1_3 = csv.writer(rq1_3_csv, delimiter=',', quotechar='"', quoting=csv.QUOTE_MINIMAL)
            writer2 = csv.writer(rq2_csv, delimiter=',', quotechar='"', quoting=csv.QUOTE_MINIMAL)
            
            writer2.writerow(['Time to generate a test', 'Time to run a test'])
            
            num_tests = 1
            start_time = datetime.now()
            global interesting_test_cases
            interesting_test_cases = 0
            self.coverage.start()
            
            # to run for 1hr
            while ((datetime.now()-start_time).total_seconds() < 60*60 ):
            # while True:
                seed = self.choose_next()
                print(seed)
                energy = self.assign_energy(seed)
                serializer = Serializer()
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                # check for timeout events
                sock.settimeout(2)
                
                # generate random request
                for i in range(energy):
                    start_time_per_test = datetime.now()
                    
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
                    
                    # RQ 2 time to generate test
                    end_time_gen_test = datetime.now()
                    elapsed_time_gen_test = (end_time_gen_test - start_time_per_test).total_seconds() * 1000.0

                    # send request
                    datagram = serializer.serialize(req) 
                    sock.sendto(datagram, req.destination)
                    # try to receive response
                    try:
                        datagram, source = sock.recvfrom(4096)
                    # handle timeouts (server crash / no response)
                    except socket.timeout:                  
                        print("Timeout")
                        p.kill()
                        _,stderr = p.communicate()
                        if stderr:
                            if stderr not in unique_bugs:
                                if "'ascii' codec can't decode byte" not in stderr:
                                    self.unique_bug_recording(req, stderr)
                                else:
                                    # Deal with ascii error as the position may vary
                                    if not ascii_error_found:
                                        ascii_error_found = True
                                        self.unique_bug_recording(req, stderr)
                        print("Server crashed. Restarting")
                        with open("crashed_log.txt", "a") as f:
                            f.write("Request:\n" + req.pretty_print())
                            f.write("\n")
                        p = start_server()
                        continue
                    received_message = serializer.deserialize(datagram, source) # response
                    print(received_message.pretty_print())
                    # check if coverage increased
                    self.coverage.stop()
                    self.coverage.save()
                    if self.is_interesting():
                        interesting_test_cases += 1
                        self.seed_queue.append(mutated_seed)   
                        self.seed_queue[0]["pheromone"] += pheromone_increase
                    self.coverage.start()
                    lap_time = datetime.now()
                    elapsed_time = (lap_time - start_time).total_seconds() * 1000.0
                    # RQ 2 time to run test
                    end_time_run_test = datetime.now()
                    elapsed_time_run_test = (end_time_run_test - start_time_per_test).total_seconds() * 1000.0
                        
                    # write to excel for plotting of RQ
                    # RQ1_1
                    writer1_1.writerow([len(unique_bugs), elapsed_time])
                    # RQ1_2
                    writer1_2.writerow([interesting_test_cases, elapsed_time])
                    # RQ1_3
                    writer1_3.writerow([interesting_test_cases, num_tests])
                    # RQ2
                    writer2.writerow([elapsed_time_gen_test, elapsed_time_run_test])
                    
                    num_tests += 1
        print(unique_bugs)
        self.writeToRq4Csv()

    def unique_bug_recording(self, request, error):
        unique_bugs.append(error)
        print("New unique error detected:"), error
        with open("error_recording.txt", "a") as f:
            f.write("Request:\n" + request.pretty_print())
            f.write("\n")
            f.write("Error:\n" + error)
            f.write("\n")

    def close_connection(self):
        self.client.stop()
    
    def mutate_input(self, input_data, key):
        mutations = ("bitflip", "byteflip", "arith inc/dec", "interesting values", 
                     "random bytes", "delete bytes", "insert bytes", "overwrite bytes", 
                     "cross over")
        mutation_chose = random.choice(mutations)
        mutated_data = self.apply_mutation(input_data, mutation_chose, key)
        return mutated_data
    
    def apply_mutation(self, data, mutation, key):
        if data == "" or data is None:
            if key == "token":
                data = ''.join(random.choice(string.printable) for i in range(10)) 
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
            if self.seed_queue[0]["pheromone"] > 0:
                self.seed_queue[0]["pheromone"] += pheromone_decrease
            print(self.seed_queue[0]["pheromone"])
            return self.seed_queue[0]
        return "Seed queue is empty"
    
    def is_interesting(self):
        # Get the coverage data before
        if self.coverage_before is None:
            self.coverage_before = self.coverage.json_report(pretty_print=True)
            return True

        # Get the new coverage data
        coverage_after = self.coverage.json_report(pretty_print=True)
        # Check if coverage has increased
        if self.coverage_before != coverage_after:
            self.coverage_before = coverage_after
            return True
        return False
    
    def assign_energy(self, seed):
        # ant colony optimisation
        return seed["pheromone"] + 1

    
    def signal_handler(self, sig, frame):
        # subprocess.Popen(["coverage", "report", "-m"])
        # subprocess.Popen(["coverage", "html"])
        #with open("seed.json", "w") as f:
            #json.dump(self.seed_queue, f)
        self.coverage.stop()
        print(self.coverage.report())
        print("Number of bugs found:", len(unique_bugs))
        print("Number of interesting test cases:", interesting_test_cases)
        print("Exiting...")
        self.writeToRq4Csv()
        
        exit(0)   
    
    def writeToRq4Csv(self):
        # rmb to save each session for RQ4 as different csv (change the name RQ4_Sx)
        with open ('RQ/RQ4_S1.csv', 'wb') as rq4_csv:
            # RQ4
            writer4 = csv.writer(rq4_csv, delimiter=',', quotechar='"', quoting=csv.QUOTE_MINIMAL)
            writer4.writerow(['No. of interesting tests', 'No. of unique crashes'])
            writer4.writerow([interesting_test_cases, len(unique_bugs)])

    
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