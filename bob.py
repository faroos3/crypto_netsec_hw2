'''
This is going to be the client Bob aka A for Cryptography and Network Security HW2 taught by Professor 
Yener in F18. This will connect to the KDC and through Diffie-Hellman, gets a key Ka to use in N-S with 
A. 
'''

import random
import time
import socket 
import sys
import toy_des

# define all the crypto stuff you have to do here first 

# remember you can do "{:08b}".format(any number) to convert that number to a string rep of its binary digits 
# "{:010b}".format(any number) for 10 bits

# information in the public space is global
ID_A = '1110010101' # this is going to be ID_A used in N-S
ID_B = '0010010110' # this is going to be the ID_B used in N-S
g = 331 
n = 1021

# An assumption made is that the host and port B will wait for A on was shared securely between the two
my_host = "127.0.0.1"
my_port = 8889

def generate_a():
	a = random.randint(1, n)
	return a

def generate_nonce():
	nonce = random.randint(1, 1024)
	return nonce

def encryptor(entire_msg, key):
	K1, K2 = toy_des.key_getter(key)
	# see, I'm going to operate under the assumption that entire_msg is already in bits 
	# so I don't need to do text_to_bits
	# turning bits to bits because it'll convert easier lollllllll 
	bits_of_bits = toy_des.text_to_bits(entire_msg)
	block_list = []
	block = ""
	for i in range(0, len(bits_of_bits), 8):
		for j in range(i, i+8):
			if j == len(bits_of_bits):
				break
			block += bits_of_bits[j]
		block_list.append(block)
		block = ""

	encrypt_list = []
	encrypt_string = ""
	for i in range(len(block_list)):
		encrypt_list.append(toy_des.encryptor(block_list[i], K1, K2))

	for i in range(len(encrypt_list)):
		encrypt_string += toy_des.text_from_bits(encrypt_list[i])

	return encrypt_string

# wrapper function that usess my toy_des decryptor
def decryptor(entire_msg, key):
	K1, K2 = toy_des.key_getter(key)
	decrypt_list = []
	encrypt_bits = toy_des.text_to_bits(entire_msg)

	block = ""
	for i in range(0, len(encrypt_bits), 8):
		for j in range(i, i+8):
			# print(j)
			block += encrypt_bits[j]
		decrypt_list.append(block)
		block = ""

	decrypt_bits = []
	for i in range(len(decrypt_list)):
		decrypt_bits.append(toy_des.decryptor(decrypt_list[i], K1, K2))
	block = ""
	for i in range(len(decrypt_bits)):
		block += toy_des.text_from_bits(decrypt_bits[i])

	return block

##############################################################################
#### ALL THE NETWORKING STUFF HAPPENS BELOW #### 
##############################################################################

# the following was shamelessley stolen from: https://kuntalchandra.wordpress.com/2017/08/23/python-socket-programming-server-client-application-using-threads/
def client_connect():
    soc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    host = "127.0.0.1"
    port = 8888
    max_buffer_size = 5120
    buffer_size = 0
    try:
        soc.connect((host, port))
    except:
        print("Connection error")
        sys.exit()

    print("Enter 'quit' to exit")
    message = ID_B # that way, the first thing that sends is the ID 
    # print("BOB SENT TO THE KDC: ", message)
    soc.send(message.encode("utf8"))

    print("You have sent your ID to the server. A key exchange will now be performed between you and the server using the Diffie-Hellman key exhange algorithm.\n")

    # start the Diffie-Hellman 

    # generate an a 
    a = generate_a()
    # print("The a generated is:", a)
    to_send_to_KDC = str((g**a) % n)
    # print("Now going to send the value " +to_send_to_KDC + " to the KDC")
    # print("BOB SENT AGAIN TO THE KDC: ", to_send_to_KDC)
    soc.send(to_send_to_KDC.encode("utf8"))
    recv_from_KDC = soc.recv(max_buffer_size).decode("utf8") # this should be g^b mod n 
    Kb = ((int(recv_from_KDC))**a) % n
    Kb_bits = "{:010b}".format(Kb)
    print("The shared key with the KDC is:", Kb, "which as 10 bits is: {:010b}".format(Kb))
    soc.close()
    # D-H done 

    soc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        soc.connect((host, port))
    except:
        print("Connection error 2")
        sys.exit()

    message = ID_B # that way, the first thing it sends is the ID
    soc.send(message.encode("utf8"))
    print("You have connected to the KDC again. Please select what you would like to do.")
    print("Type in 'list' to see who has spoken with the KDC.")
    print("Type in 'wait' to wait on a client Alice to initiate a Needham-Schroder talk with you.")
    # print("Type in 'talk to <ID>', where <ID> is the 10-bit ID of someone else who has spoken with the KDC to initiate N-S with them.") 
    print("Please note: For the sake of this proof of concept, the other client should be listeining for a connection when it connects. You, as Alice, will be disconnecting from the KDC and then connecting to them.")
    print("Type in 'quit' to close the program.")
    while True:
    	message = input("--> ")
    	# list 
    	if(message == 'list'):
    		soc.send(message.encode("utf8"))
    		list_of_clients = soc.recv(max_buffer_size).decode("utf8")
    		print(list_of_clients)
    	elif(message == "wait"): # N-S! The longest one.
    		# you wait until someone connects to you for step 3 of N-S
    		# first, close your connection with the KDC 
    		print("Closing the connection to the KDC as it is no longer needed!")
    		soc.send("quit".encode("utf8")) # so the KDC doesn't kill itself in in infy loop
    		soc.close()
    		# starting my own socket 
    		soc = socket.socket()
    		soc.bind((my_host, my_port))
    		print("I am waiting for a connection from Alice now...")
    		b_soc.listen(1)
    		# At this point, we've connected! Get their information 
    		connection, address = b_soc.accept()
    		print("Got a connection from:", str(address))
    		# now recieve the thing to verify 
    		to_decrypt = b_soc.recv(max_buffer_size).decode("utf8")
    		print("Recieved from Alice:", to_decrypt)


    	elif(message == "quit"):
    		soc.send(message.encode("utf8"))
    		print("Closing the client. Thanks!")
    		soc.close()
    		sys.exit()
    	continue

    # while message != 'quit':
    #     soc.sendall(message.encode("utf8"))
    #     if soc.recv(5120).decode("utf8") == "-":
    #         pass        # null operation

    #     message = input(" -> ")

    # soc.send(b'--quit--')

if __name__ == "__main__":

	client_connect()