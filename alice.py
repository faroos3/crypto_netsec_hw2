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

# An assumption made is that the host and port B will wait for A on was shared securely between the two
my_host = "127.0.0.1"
my_port = 8889

# Define all the crypto stuff needed up here first 

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

    try:
        soc.connect((host, port))
    except:
        print("Connection error 1")
        sys.exit()

    print("Enter 'quit' to exit")
    message = ID_A # that way, the first thing it sends is the ID
    soc.send(message.encode("utf8"))

    print("You have sent your ID to the server. A key exchange will now be performed between you and the server using the Diffie-Hellman key exhange algorithm.\n")

    # start the Diffie-Hellman 

    # generate an a 
    a = generate_a()
    # print("The a generated is:", a)
    to_send_to_KDC = str((g**a) % n)
    # print("Now going to send the value " +to_send_to_KDC + " to the KDC")
    soc.send(to_send_to_KDC.encode("utf8"))
    recv_from_KDC = soc.recv(max_buffer_size).decode("utf8") # this should be g^b mod n 
    Ka = ((int(recv_from_KDC))**a) % n
    Ka_bits = "{:010b}".format(Ka)
    print("The shared key with the KDC is:", Ka, "which as 10 bits is: {:010b} \n".format(Ka))
    soc.close()
    # Diffie-Hellman done

    # now I am going to follow the slides. A will connect to the KDC to see who is avaliable to talk.
    # Once Bob is an avaliable option, the first two steps of N-S between the KDC and A will be done
    # and the connection with the KDC will be done. I'll have B open a socket for A to connect to.
    # B and A will send each other stuff as N-S calls for, but if any of it fails at any time, then B 
    # will terminate the connection. Once it is done, they can use the session key generated by the KDC 
    soc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        soc.connect((host, port))
    except:
        print("Connection error 2")
        sys.exit()

    message = ID_A # that way, the first thing it sends is the ID
    soc.send(message.encode("utf8"))
    print("You have connected to the KDC again. Please select what you would like to do.")
    print("Type in 'list' to see who has spoken with the KDC.")
    print("Type in 'talk' to initiate a N-S with the KDC.")
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
    	elif(message == "talk"): # N-S! The longest one.
    		soc.send(message.encode("utf8"))
    		client_desired = input("Please enter the 10-bit public of a client you want to talk with --> ")
    		soc.send(client_desired.encode("utf8"))
    		response = soc.recv(max_buffer_size).decode("utf8")
    		print(response, "was recieved from client.")
    		if("ERROR" in response):
    			print("Oh no! I sent an ID that didn't work.")
    			continue
    		else: # GOOD CASE
    			print("Going to send the first the first envelope to the KDC.")
    			# STEP 1 
    			nonce_1 = generate_nonce()
    			nonce_1_bits = "{:010b}".format(nonce_1)
    			print("The nonce generated is", nonce_1, "which as 10 bits is", nonce_1_bits)
    			first_envolope = ID_A + ID_B + nonce_1_bits
    			print("About to send the first_envolope", first_envolope)
    			soc.send(first_envolope.encode("utf8"))
    			# END STEP 1
    			# START STEP 2 
    			# this should be receiveing an envelope from the KDC 
    			second_envolope = soc.recv(max_buffer_size).decode("utf8")
    			print("Recieved this from the KDC:", second_envolope)
    			# END STEP 2 
    			# START STEP 3
    			# first, decrypt the thing I just got 
    			decrypted_second_env = decryptor(second_envolope, Ka_bits)
    			print("I decrypted the received envelope with my key and got:", decrypted_second_env)
    			# the first ten bits should be the session key, the second 10 bits should be B's ID, the third as the nonce. Anything after 
    			# has to be sent to B 
    			Ks = decrypted_second_env[0:10]
    			print("Ks got is:", Ks)
    			check_ID_B = decrypted_second_env[10:20]
    			print("ID_B == check_ID_B?", check_ID_B == ID_B)
    			nonce = decrypted_second_env[20:30]
    			print(nonce, "was the nonce received.")
    			send_to_B = decrypted_second_env[30::]
    			print("need to send this to b:", send_to_B)

    			# now need to close the connection to the KDC and connect to B's socket 
    			print("Closing the connection to the KDC as it is no longer needed!")
    			soc.send("quit".encode("utf8")) # so the KDC doesn't kill itself in in infy loop
    			soc.close()
    			# Now to connect to B's socket!
    			soc = socket.socket()
    			try:
    				soc.connect((my_host, my_port))
    			except:
    				print("B does not have their port up yet! Try again later.")
    				continue
    			# now send the thing to send to B 
    			soc.send(send_to_B.encode("utf8"))


    			# END STEP 3 
    	elif(message == "quit"):
    		soc.send(message.encode("utf8"))
    		print("Closing the client. Thanks!")
    		soc.close()
    		sys.exit()
    	continue

    # while message != 'quit':
    #     soc.sendall(message.encode("utf8"))
    #     if soc.recv(max_buffer_size).decode("utf8") == "-":
    #         pass        # null operation

    #     message = input(" -> ")

    # soc.send(b'--quit--')

if __name__ == "__main__":
	client_connect()