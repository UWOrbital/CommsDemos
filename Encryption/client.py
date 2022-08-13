from base64 import b64decode
import socket
from encryption_functions import encrypt


HOST = "127.0.0.1"  
PORT = 8080  

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect((HOST, PORT))
    while True:
      # String
      user_input = input("Enter data: ")
      # Also a String
      user_input = encrypt.encrypt(str.encode(user_input))
      
      # Send hex byte array
      s.sendall((b64decode(user_input).hex()).encode())
      data = s.recv(10000)
      response = data.decode()
      print("Client responded with:", response)
      if response == "exit":
        break