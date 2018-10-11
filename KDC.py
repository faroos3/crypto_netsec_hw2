'''
This is going to be the KDC for Cryptography and Network Security HW 2 at RPI taught by Prof. Yener.

Alice and Bob will connect to this, and this does Diffie-Hellman with each of them to generate a Ka and a Kb.
'''

import random
import time
import sys 
import socket
import traceback
from threading import Thread

# do all the crypto stuff first 

# information in the public space is global
ID_A = '1110010101' # this is going to be ID_A used in N-S
ID_B = '0010010110' # this is going to be the ID_B used in N-S
g = 331 
n = 1021

# this function takes as input g, a, b, and n and returns 
# what the key will be in bit form 
def diffie_hellman(n, g, a, b):
	expo = a*b # what the g exponent will be 
	big_g = g**expo
	new_key = big_g % n

	return new_key

# this returns a 10 bit key that is going to be used in encryption
# remember, just a string of len 10 composed of 0 and 1 
def generate_session_key():
	K_s = ""
	num = 0
	for i in range(10):
		num = random.randint(0,1)
		K_s += str(num)
	return K_s

##############################################################################
#### ALL THE NETWORKING STUFF HAPPENS BELOW #### 
##############################################################################

# the following was shamelessley stolen from: https://kuntalchandra.wordpress.com/2017/08/23/python-socket-programming-server-client-application-using-threads/

def start_server():
    host = "127.0.0.1"
    port = 8888         # arbitrary non-privileged port

    soc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    soc.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)   # SO_REUSEADDR flag tells the kernel to reuse a local socket in TIME_WAIT state, without waiting for its natural timeout to expire
    print("Socket created")

    try:
        soc.bind((host, port))
    except:
        print("Bind failed. Error : " + str(sys.exc_info()))
        sys.exit()

    soc.listen(3)       # queue up to 3 requests
    print("KDC now listening")

    ######################### Input my crypto stuff 

    id_list = {} # dictionary to keep track of which clients have connected or not

    Ks = generate_session_key()
    print("The session key is going to be", Ks)

    ##########################

    # infinite loop- do not reset for every requests
    while True:
        connection, address = soc.accept()
        ip, port = str(address[0]), str(address[1])
        print("Connected with " + ip + ":" + port)

        try:
            Thread(target=client_thread, args=(connection, ip, port)).start()
        except:
            print("Thread did not start.")
            traceback.print_exc()

    soc.close()

def client_thread(connection, ip, port, max_buffer_size = 5120):
    is_active = True

    while is_active:
        client_input = receive_input(connection, max_buffer_size)

        if "--QUIT--" in client_input:
            print("Client is requesting to quit")
            connection.close()
            print("Connection " + ip + ":" + port + " closed")
            is_active = False
        else:
            print("Processed result: {}".format(client_input))
            connection.sendall("-".encode("utf8"))


def receive_input(connection, max_buffer_size):
    client_input = connection.recv(max_buffer_size)
    client_input_size = sys.getsizeof(client_input)

    if client_input_size > max_buffer_size:
        print("The input size is greater than expected {}".format(client_input_size))

    decoded_input = client_input.decode("utf8").rstrip()  # decode and strip end of line
    result = process_input(decoded_input)

    return result

def process_input(input_str):
	print("Getting the ID from the client")
	return "Hello " + str(input_str).upper()


if __name__ == "__main__":
	# this needs to listen to TCP connection 
	# to first do diffie-hellman 

	# upon a client connecting to KDC, 
	# it will send their ID (hardcoded)
	# if it's the first time a client with that ID connected, 
	# diffie-hellman will be done and a shared key 
	# will be established. The second time a client connects, 
	# it then wants to do N-S. 

	start_server() 

	K_s = generate_session_key()
	print(K_s)