from coapthon.client.helperclient import HelperClient
from coapthon.messages.request import Request
from coapthon import defines
from coapthon.serializer import Serializer
import subprocess
import socket
import random
import string
from time import sleep
#sudo gdb -ex run -ex backtrace --args python2 coapserver.py -i 127.0.0.1 -p 5683 
class CoAPFuzzer:
    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.client = HelperClient(server=(self.host, self.port))
        self.original_payload = "Hello, CoAP!"
        self.seed_queue = []
        self.failure_queue = []
        self.timeout_count = 0

    def fuzz_payload(self, payload, num_bytes):
        # Generate random bytes to replace part of the payload
        fuzz_bytes = ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(num_bytes))
        return payload[:3] + fuzz_bytes + payload[3 + num_bytes:]

    def fuzz_and_send_requests(self, num_requests, num_bytes):
        
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
            req.uri_path = random.choice(["/basic/", "/storage/", "/separate/", "/long/", "/big/", "/void/", "/xml/", "/encoding/", "/etag/", "/child/", "/advanced/", "/advancedSeparate/", "/"])
            #req.uri_query = random.choice(["@1312", "first=1&second=2", "first=1&second=2&third=3", "first=1&second=2&third=3&fourth=4", "first=1&second=2&third=3&fourth=4&fifth=5", "first=1&second=2&third=3&fourth=4&fifth=5&sixth=6", "first=1&second=2&third=3&fourth=4&fifth=5&sixth=6&seventh=7", "first=1&second=2&third=3&fourth=4&fifth=5&sixth=6&seventh=7&eighth=8", "first=1&second=2&third=3&fourth=4&fifth=5&sixth=6&seventh=7&eighth=8&ninth=9", "first=1&second=2&third=3&fourth=4&fifth=5&sixth=6&seventh=7&eighth=8&ninth=9&tenth=10"])
            req.accept = random.choice([2, "adafsas", defines.Content_types["text/plain"], defines.Content_types["application/link-format"], defines.Content_types["application/xml"], defines.Content_types["application/octet-stream"], defines.Content_types["application/exi"], defines.Content_types["application/json"]])
            req.payload = fuzzed_payload
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
                    if self.timeout_count > 2:
                        self.timeout_count = 0
                        self.close_connection()
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

    def mutate_input(self, input_data):
        mutation_probability = 0.1
        mutated_data = input_data.copy()
        for i in input_data:
            if random.random() < mutation_probability:
                mutated_data[i] = self.apply_mutation(mutated_data[i])

        return mutated_data
    
    def choose_next(self):
        return random.choice(self.seed_queue)
    
    def is_interesting(self):

        pass

    
def main():
    host = "127.0.0.1"
    port = 5683
    subprocess.Popen(["gdb", "-ex", "run", "-ex", "backtrace", "--args", "python2", "coapserver.py", "-i", host, "-p", str(port)])
    fuzzer = CoAPFuzzer(host, port)
    #while(1):
    #    try:
    sleep(1)
    fuzzer.fuzz_and_send_requests(num_requests=3, num_bytes=5)
    #    except:
    fuzzer.close_connection()

if __name__ == "__main__":
    main()
