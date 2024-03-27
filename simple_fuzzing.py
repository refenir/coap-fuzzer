import os
import signal
from coapthon.client.helperclient import HelperClient
from coapthon.messages.request import Request
from coapthon import defines
from coapthon.serializer import Serializer
import subprocess
import socket
import random
import string
from time import sleep
#gdb -ex run -ex backtrace --args python2 coapserver.py -i 127.0.0.1 -p 5683 
class CoAPFuzzer:
    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.client = HelperClient(server=(self.host, self.port))
        self.original_payload = "Hello, CoAP!"
        self.seed_queue = ["Meow"]
        self.failure_queue = []
        self.timeout_count = 0

    def fuzz_payload(self, payload, num_bytes):
        # Generate random bytes to replace part of the payload
        fuzz_bytes = ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(num_bytes))
        return payload[:3] + fuzz_bytes + payload[3 + num_bytes:]

    def fuzz_and_send_requests(self, num_requests, num_bytes, server_process):
        
        while True:
            fuzzed_payload = self.fuzz_payload(self.original_payload, num_bytes)
            print("Fuzzing payload:", fuzzed_payload)

            # Send fuzzed GET request with the fuzzed payload and path "/basic/"
            req = Request()
            serializer = Serializer()
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(10)
            req.type = random.choice([defines.Types["CON"], defines.Types["NON"], defines.Types["ACK"], defines.Types["RST"]])
            req.code = random.choice([defines.Codes.GET.number, defines.Codes.POST.number, defines.Codes.PUT.number, defines.Codes.DELETE.number]) # Everytime EMPTY is chosen, the server will give up, but not crash
            #req.token = ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(1)) # If string is 100 letters long, the server will crash
            req.token = ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(random.randint(1,100))) # If string is 100 letters long, the server will crash
            # req.token = self.mutate_input("RtNPMtgHjswg56RkhNEvc7cNplXPUIrOFFXgFq6s6hlTqjuqxDOHyxTGMg")
            req.uri_path = random.choice(["/basic/", "/storage/", "/separate/", "/long/", "/big/", "/void/", "/xml/", "/encoding/", "/etag/", "/child/", "/advanced/", "/advancedSeparate/", "/"])
            #req.uri_query = random.choice(["@1312", "first=1&second=2", "first=1&second=2&third=3", "first=1&second=2&third=3&fourth=4", "first=1&second=2&third=3&fourth=4&fifth=5", "first=1&second=2&third=3&fourth=4&fifth=5&sixth=6", "first=1&second=2&third=3&fourth=4&fifth=5&sixth=6&seventh=7", "first=1&second=2&third=3&fourth=4&fifth=5&sixth=6&seventh=7&eighth=8", "first=1&second=2&third=3&fourth=4&fifth=5&sixth=6&seventh=7&eighth=8&ninth=9", "first=1&second=2&third=3&fourth=4&fifth=5&sixth=6&seventh=7&eighth=8&ninth=9&tenth=10"])
            req.accept = random.choice([2, "adafsas", defines.Content_types["text/plain"], defines.Content_types["application/link-format"], defines.Content_types["application/xml"], defines.Content_types["application/octet-stream"], defines.Content_types["application/exi"], defines.Content_types["application/json"]])
            req.payload = self.mutate_input(self.original_payload)
            print("Request payload:", type(req.payload))
            req.destination = (self.host, self.port)
            req.mid = random.randint(1, 65535) #required, don't change
            # add discovery/observe mutation if the request is a GET request
            if req.code == defines.Codes.GET.number:
                mutate_obs_disc = random.random()
                if mutate_obs_disc < 0.33:
                    req.observe = random.randint(0, 1)
                elif mutate_obs_disc < 0.66:
                    del req.uri_path
                    req.uri_path = defines.DISCOVERY_URL
            print(req.pretty_print())
            with open ("fuzzed requests.txt", "a") as f:
                f.write("Request:\n" + req.pretty_print())
                f.write("\n")
            datagram = serializer.serialize(req) 
            sock.sendto(datagram, req.destination)
            try:
                datagram, source = sock.recvfrom(4096)
            except socket.timeout as e:
                err = e.args[0]
                if err == "timed out":
                    sleep(1)
                    print("Received time out")
                    self.timeout_count += 1
                    if self.timeout_count == 2:
                        self.timeout_count = 0
                        self.close_connection()
                        os.killpg(os.getpgid(server_process.pid), signal.SIGTERM)
                        main()
                        break
                    continue
                else:
                    print(e)
                    self.close_connection()
            except socket.error as e:
                print(e)
                self.close_connection()
            else:   
                received_message = serializer.deserialize(datagram, source)# response
                print(received_message.pretty_print())
                with open ("fuzzed requests.txt", "a") as f:
                    f.write("Received:\n" + received_message.pretty_print())
                    f.write("\n")
            sleep(0.5)

    def close_connection(self):
        self.client.stop()

    # def mutate_input(self, input_data):
    #     mutation_probability = 0.1
    #     mutated_data = input_data.copy()
    #     for i in input_data:
    #         if random.random() < mutation_probability:
    #             mutated_data[i] = self.apply_mutation(mutated_data[i])

    #     return mutated_data
    
    def mutate_input(self, input_data):
        # print(f"Input data: {input_data.pretty_print()}")
        mutations = ("bitflip", "byteflip", "arith inc/dec", "interesting values", "user extras", "auto extras", "random bytes", "delete bytes", "insert bytes", "overwrite bytes", "cross over")
        mutation_chose = mutations[random.randint(0,len(mutations)-1)]
        mutated_data = self.apply_mutation(input_data, mutation_chose)
        # print(f"Mutated data: {mutated_data}")
        return mutated_data
    
    def choose_next(self):
        return random.choice(self.seed_queue)
    
    def is_interesting(self):

        pass

    def apply_mutation(self, data, mutation):
        mutated_input = bytearray()
        mutated_input.extend(data.encode("utf-8"))
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
        elif mutation == "user extras":
            operation = random.choice(("overwrite", "insert"))                
            if operation == "overwrite":
                pass
            elif operation == "insert":
                pass
        elif mutation == "auto extras":
            pass
        elif mutation == "random bytes":
            byte_index = random.randint(0, len(mutated_input)-1)
            mutated_input[byte_index] = random.randint(0, 255)
        elif mutation == "delete bytes":
            size = random.randint(1, 4)
            start = random.randint(0, len(mutated_input)-size)
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
            other_data.extend(data2.encode("utf-8"))
            if len(other_data) < len(mutated_input):
                splice_loc = random.randint(0, len(other_data))
            else:
                splice_loc = random.randint(0, len(mutated_input))
            mutated_input[splice_loc:] = other_data[splice_loc:]
        try:
            mutated_input = bytes(mutated_input).decode("utf-8")
        except UnicodeDecodeError:
            mutated_input =bytes(mutated_input).decode("utf-8", errors="replace")
        return mutated_input

    
def main():
    host = "127.0.0.1"
    port = 5683
    server_process = subprocess.Popen(["gdb", "-ex", "run", "-ex", "backtrace", "--args", "python2", "coapserver.py", "-i", host, "-p", str(port)], stdout=subprocess.PIPE, stderr=subprocess.PIPE, preexec_fn=os.setsid)  
    fuzzer = CoAPFuzzer(host, port)
    #while(1):
    #    try:
    sleep(1)
    fuzzer.fuzz_and_send_requests(num_requests=3, num_bytes=5, server_process=server_process)
    #    except:
    fuzzer.close_connection()

if __name__ == "__main__":
    main()
