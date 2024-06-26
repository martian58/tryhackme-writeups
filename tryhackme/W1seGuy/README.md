# W1seGuy

A w1se guy 0nce said, the answer is usually as plain as day.

## Server.py
```python
import random
import socketserver 
import socket, os
import string

flag = open('flag.txt','r').read().strip()

def send_message(server, message):
    enc = message.encode()
    server.send(enc)

def setup(server, key):
    flag = 'THM{thisisafakeflag}' 
    xored = ""

    for i in range(0,len(flag)):
        xored += chr(ord(flag[i]) ^ ord(key[i%len(key)]))

    hex_encoded = xored.encode().hex()
    return hex_encoded

def start(server):
    res = ''.join(random.choices(string.ascii_letters + string.digits, k=5))
    key = str(res)
    hex_encoded = setup(server, key)
    send_message(server, "This XOR encoded text has flag 1: " + hex_encoded + "\n")
    
    send_message(server,"What is the encryption key? ")
    key_answer = server.recv(4096).decode().strip()

    try:
        if key_answer == key:
            send_message(server, "Congrats! That is the correct key! Here is flag 2: " + flag + "\n")
            server.close()
        else:
            send_message(server, 'Close but no cigar' + "\n")
            server.close()
    except:
        send_message(server, "Something went wrong. Please try again. :)\n")
        server.close()

class RequestHandler(socketserver.BaseRequestHandler):
    def handle(self):
        start(self.request)

if __name__ == '__main__':
    socketserver.ThreadingTCPServer.allow_reuse_address = True
    server = socketserver.ThreadingTCPServer(('0.0.0.0', 1337), RequestHandler)
    server.serve_forever()
```

## Solution with python 

```python
import binascii
import string
import itertools
from concurrent.futures import ThreadPoolExecutor, as_completed
import argparse

def extract_initial_key_part(encrypted_hex, known_prefix):
    encrypted_bytes = binascii.unhexlify(encrypted_hex)
    min_len = min(len(encrypted_bytes), len(known_prefix))
    initial_key_part = ""

    for i in range(min_len):
        initial_key_part += chr(encrypted_bytes[i] ^ ord(known_prefix[i]))

    return initial_key_part

def xor_decrypt(hex_string, key):
    encrypted_bytes = binascii.unhexlify(hex_string)
    decrypted_text = ''.join(chr(encrypted_bytes[i] ^ ord(key[i % len(key)])) for i in range(len(encrypted_bytes)))
    return decrypted_text

def validate_key(key, hex_string, known_prefix, known_suffix):
    decrypted_text = xor_decrypt(hex_string, key)
    if decrypted_text.startswith(known_prefix) and decrypted_text.endswith(known_suffix):
        return key, decrypted_text
    return None

def generate_and_validate_keys(hex_string, known_prefix, known_suffix, key_prefix):
    key_length = 5
    remaining_chars = key_length - len(key_prefix)
    valid_chars = string.ascii_letters + string.digits
    valid_results = []

    with ThreadPoolExecutor(max_workers=8) as executor:
        future_tasks = []
        possible_keys = (key_prefix + ''.join(combination) for combination in itertools.product(valid_chars, repeat=remaining_chars))

        for key in possible_keys:
            future_tasks.append(executor.submit(validate_key, key, hex_string, known_prefix, known_suffix))

        for future in as_completed(future_tasks):
            result = future.result()
            if result:
                valid_results.append(result)

    return valid_results

def main():
    parser = argparse.ArgumentParser(description='Decrypt XOR-encoded data and find the key.')
    parser.add_argument('-e', '--encrypted', type=str, help='Hex-encoded encrypted data', required=True)

    args = parser.parse_args()

    known_prefix = "THM{"  # Start of the flag
    known_suffix = "}"  # End of the flag

    initial_key_part = extract_initial_key_part(args.encrypted, known_prefix)
    print(f"Derived Key Prefix: {initial_key_part}")

    try:
        valid_flags = generate_and_validate_keys(args.encrypted, known_prefix, known_suffix, initial_key_part)
        if valid_flags:
            for key, flag in valid_flags:
                print(f"Identified Key: {key}")
                print(f"Decrypted Flag: {flag}")
        else:
            print("No valid flag found.")
    except Exception as error:
        print(f"An error occurred: {error}")

if __name__ == "__main__":
    main()

```