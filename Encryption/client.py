import socket
# from cryptography.fernet import Fernet

# AES-128-CBC HMAC-SHA256 encryption PKCS7 padding

# key = b'35tTVCRKHT6cjysubu3_x3t4MbldT_ct8tV284mWBm0='
# f = Fernet(key)
# token = f.encrypt(b"A really secret message. Not for prying eyes.")
# print(f.decrypt(token).decode())

HOST = "127.0.0.1"  
PORT = 8080  

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect((HOST, PORT))
    while True:
      user_input = input("Enter data: ")
      s.sendall(user_input)
      # token = f.encrypt(user_input.encode())
      # s.sendall(token)
      data = s.recv(1024)
      response = data.decode()
      print("Client responded with:", response)
      if response == "exit":
        break