'''
This is going to be the client Bob aka A for Cryptography and Network Security HW2 taught by Professor 
Yener in F18. This will connect to the KDC and through Diffie-Hellman, gets a key Ka to use in N-S with 
A. 
'''

import random
import time
import socket 
import sys

# define all the crypto stuff you have to do here first 

# information in the public space is global
ID_A = '1110010101' # this is going to be ID_A used in N-S
ID_B = '0010010110' # this is going to be the ID_B used in N-S
g = 331 
n = 1021

##############################################################################
#### ALL THE NETWORKING STUFF HAPPENS BELOW #### 
##############################################################################

# the following was shamelessley stolen from: https://kuntalchandra.wordpress.com/2017/08/23/python-socket-programming-server-client-application-using-threads/
def client_connect():
    soc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    host = "127.0.0.1"
    port = 8888

    try:
        soc.connect((host, port))
    except:
        print("Connection error")
        sys.exit()

    print("Enter 'quit' to exit")
    message = input(" -> ")

    while message != 'quit':
        soc.sendall(message.encode("utf8"))
        if soc.recv(5120).decode("utf8") == "-":
            pass        # null operation

        message = input(" -> ")

    soc.send(b'--quit--')

if __name__ == "__main__":

	client_connect()