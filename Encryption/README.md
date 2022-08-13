There are a few things that need to be installed to use the encryption libraries.

For Python:
  Create your python environment:
  ```zsh
    python3 -m venv venv
    For Mac: source venv/bin/activate
    For Windows: venv\Scripts\activate
    python3 -m pip install cryptography
  ```

For C:
  Install OpenSSL library (https://www.openssl.org/source/)
  cd into the folder where it's located and run the following commands:
  ```zsh
    tar -xvf openssl-1.1.1q.tar.gz
    cd openssl-1.1.1q
    ./config shared --prefix=<FULL_PATH_TO_WORKING_DIRECTORY>  (Ex. /Users/mahfuzur/Documents/Projects/CommsDemos/Encryption)
    make
    make install
  ```


You should see an include and lib folder in the Encryption folder now.
Now go to this folder (Encryption) and run the following commands to start the C server:
```zsh
  gcc server.c encryption_functions/encrypt.c -o output -I ./include -L ./lib -lcrypto
  ./output
```

In a new terminal run the python client and start typing messages to send to the server

```zsh
  python3 client.py
```
