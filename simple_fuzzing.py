from coapthon.client.helperclient import HelperClient
from coapthon.messages.request import Request
from coapthon import defines
from coapthon.serializer import Serializer
import socket
import random
import string
from time import sleep
from time import time
import subprocess

timeout = time() + 60

def restart_server():
    command = ["python", "coapserver.py"] 
    try:
        subprocess.Popen(command)
        print("CoAP server restarted")
    except Exception as e:
        print("Error restarting CoAP server: ", str(e))

class CoAPFuzzer:
    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.client = HelperClient(server=(self.host, self.port))
        self.original_payload = "Hello, CoAP!"
            
    def fuzz_payload(self, payload, num_bytes):
        # Generate random bytes to replace part of the payload
        fuzz_bytes = ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(num_bytes))
        return payload[:3] + fuzz_bytes + payload[3 + num_bytes:]

    def fuzz_and_send_requests(self, num_requests, num_bytes):
        while True:
            if time() > timeout:
                break
            try:
                fuzzed_payload = self.fuzz_payload(self.original_payload, num_bytes)
                print("Fuzzing payload:", fuzzed_payload)

                # Send fuzzed GET request with the fuzzed payload and path "/basic/"
                req = Request()
                serializer = Serializer()
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                req.type = random.choice([defines.Types["CON"], defines.Types["NON"], defines.Types["ACK"], defines.Types["RST"]])
                req.code = random.choice([defines.Codes.EMPTY.number, defines.Codes.GET.number, defines.Codes.POST.number, defines.Codes.PUT.number, defines.Codes.DELETE.number]) # Everytime EMPTY is chosen, the server will give up, but not crash
                req.token = ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(random.randint(1, 100))) # If string is 100 letters long, the server will crash
                req.uri_path = random.choice(["/basic/", "/storage/", "/separate/", "/long/", "/big/", "/void/", "/xml/", "/encoding/", "/etag/", "/child/", "/advanced/", "/advancedSeparate/"])
                req.payload = fuzzed_payload
                req.destination = (self.host, self.port)
                req._mid = random.randint(1, 65535) #required, don't change
                print(req.pretty_print())
                with open ("fuzzed requests.txt", "a") as f:
                    f.write("Request:\n" + req.pretty_print())
                    f.write("\n")
                datagram = serializer.serialize(req) 
                sock.sendto(datagram, req.destination)
                datagram, source = sock.recvfrom(4096)
                received_message = serializer.deserialize(datagram, source)# response
                print(received_message.pretty_print())
                with open ("fuzzed requests.txt", "a") as f:
                    f.write("Received:\n" + received_message.pretty_print())
                    f.write("\n")
                sleep(1)
            except Exception as e:
                print("Server crashed. Restarting")
                restart_server()
                self.client = HelperClient(server=(self.host, self.port))
                serializer = Serializer()
                continue

    def close_connection(self):
        self.client.stop()

    def mutate_input(self, input_data):
        mutation_probability = 0.1
        mutated_data = input_data.copy()
        for i in input_data:
            if random.random() < mutation_probability:
                mutated_data[i] = self.apply_mutation(mutated_data[i])

        return mutated_data
    
def main():
    host = "127.0.0.1"
    port = 5683

    fuzzer = CoAPFuzzer(host, port)
    #while(1):
    #    try:
    fuzzer.fuzz_and_send_requests(num_requests=3, num_bytes=5)
    #    except:
    fuzzer.close_connection()

if __name__ == "__main__":
    main()
