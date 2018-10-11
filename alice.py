'''
This is going to be the client Alice aka A for Cryptography and Network Security HW2 taught by Professor 
Yener in F18. This will connect to the KDC and through Diffie-Hellman, gets a key Ka to use in N-S with 
KDC and B. 
'''

import random
import time
import socket 
import sys 
import toy_des

# remember you can do "{:08b}".format(any number) to convert that number to a string rep of its binary digits 
# "{:010b}".format(any number) for 10 bits

# information in the public space is global
ID_A = '1110010101' # this is going to be ID_A used in N-S
ID_B = '0010010110' # this is going to be the ID_B used in N-S
g = 331 
n = 1021

# Define all the crypto stuff needed up here first 

def generate_a():
	a = "" # a should probably be an int
	return a


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

	# crypto stuff first 

	# first we want Alice to get an ID 



	client_connect()