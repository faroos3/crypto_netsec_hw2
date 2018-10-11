'''
This is going to be the KDC for Cryptography and Network Security HW 2 at RPI taught by Prof. Yener.

Alice and Bob will connect to this, and this does Diffie-Hellman with each of them to generate a Ka and a Kb.

Using this video to help me out with Diffie-Hellman: https://www.youtube.com/watch?v=Yjrfm_oRO0w

g and n are public numbers. g is a small prime number, whereas n is a reallllly big number. Alice and Bob pick two numbers a and b which are 1 <= a | b <= n.
n is often 4000 bits long, don't think I'll have mine be that big but whatever. 
a and b are selected by the KDC and are kept private between A and B. I guess it would send what it picks to Alice/Bob? 

According to our slides, g is alpha and q is n, and n/q has to be prime.

The KDC should be a client whereas Alice and Bob will be clients that connect to it. 

On Alice's side (a client), it computes (g^a)mod n. 
On Bob's side (another client), it computes (g^b)mod n. 

Bob sends the g^b mod n and Alice sends g^a mod n, and they computer (g^a)^b mod n and (g^b)^a mod n and that's the private key. 

This is done between Alice and the KDC, and then Bob and the KDC. 
'''

import random
import time
import sys 
import socket
import traceback
from threading import Thread
import toy_des

# do all the crypto stuff first 

# remember you can do "{:08b}".format(any number) to convert that number to a string rep of its binary digits 
# "{:010b}".format(any number) for 10 bits

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