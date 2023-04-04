import subprocess
decoding = True
encoding = False

#compile into exe files using commands:
#gcc -o encode.exe encode.c -L/usr/local/lib -I/usr/local/include -lcorrect
#gcc -o decode.exe decode.c -L/usr/local/lib -I/usr/local/include -lcorrect

if decoding:
    subprocess.run("./decode.exe", check=True)

if encoding:
    message_to_encode = b'hello world';
    with open('to_encode.bin', 'wb') as f:
        f.write(message_to_encode)
    subprocess.run("./encode.exe", check=True)
