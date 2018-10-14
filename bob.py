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
    print("Diffie-Hellman has finished, and you have a shared key with the KDC!")
    # print("The shared key with the KDC is:", Kb, "which as 10 bits is: {:010b}".format(Kb))
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
    print("Please note: For the sake of this proof of concept, the other client will be trying to connect. You, as Bob, will be disconnecting from the KDC and oepning your own socket.")
    print("Type in 'quit' to close the program.")
    while True:
    	message = input("Enter an option --> ")
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
    		soc.listen(1)
    		# At this point, we've connected! Get their information 
    		connection, address = soc.accept()
    		print("Got a connection from:", str(address))
    		# now recieve the thing to verify 
    		to_decrypt = connection.recv(max_buffer_size).decode("utf8")
    		# print("Recieved from Alice:", to_decrypt)
    		# Now decrypt this with my key to get the Ks 
    		decrypted_from_A = decryptor(to_decrypt, Kb_bits)
    		# print("The decrypted message is:", decrypted_from_A)
    		Ks = decrypted_from_A[0:10]
    		# if anything is ever wrong, close the connection. 
    		ID_a_to_check = decrypted_from_A[10:20]
    		# print("ID_a_to_check == ID_A?", ID_a_to_check == ID_A)
    		a_nonce = decrypted_from_A[20::]
    		# print("The nonce from A is:", a_nonce)
    		# END STEP 3 
    		# STEP 4
    		# Now that we have the Ks, let's generate a nonce, encrypt it, and sent it to A. We're expecting 
    		# that nonce back - 1.
    		nonce_2 = generate_nonce()
    		expected_nonce = nonce_2 - 1
    		nonce_2_bits = "{:010b}".format(nonce_2)
    		nonce_to_send = encryptor(nonce_2_bits, Ks) # Ks should already be bits 
    		# now send the nonce to A
    		# print("nonce_to_send is:", nonce_to_send)
    		connection.send(nonce_to_send.encode("utf8"))
    		# END STEP 4 
    		# START STEP 5 
    		nonce_2_frm_A = connection.recv(max_buffer_size).decode("utf8")
    		nonce_2_frm_A = decryptor(nonce_2_frm_A, Ks)
    		if(expected_nonce != int(nonce_2_frm_A, 2)):
    			print("The expected nonce was wrong! Closing everything.")
    			connection.send("Something went wrong. Disconnecting.".encode("utf8"))
    			soc.close()
    			sys.exit()
    		else:
    			print("It worked! Establishing connection to communicate securely with A...")
    			connection.send("Okay to connect!".encode("utf8"))
    		# END STEP 5 
    			print("Alice will send a message, and then you can send a response. Enjoy chatting!")
    			while message != "QUIT":
    				if(message == "QUIT"):
    					#end_msg = "Bob is ending the connection. Goodbye!"
    					#print("Ending the chatroom...goodbye!")
    				 	encrypted_end = encryptor(end_msg, Ks)
    				 	connection.send(encrypted_end.encode("utf8"))
    				 	soc.close()
    				 	sys.exit()
    				response = connection.recv(max_buffer_size).decode("utf8")
    				decrypted_msg = decryptor(response, Ks)
    				print("Alice says (decrypted):", decrypted_msg)
    				message = input("Message to send to Alice --> ")
    				encrypted_msg = encryptor(message, Ks)
    				if(decrypted_msg == "QUIT"):
    						print("Ending the chat...goodbye!")
    						soc.close()
    						sys.exit()
    				print("\nThe message you are sending, when encrpted, is:", encrypted_msg, "\n")
    				connection.send(encrypted_msg.encode("utf8"))

    	elif(message == "quit"):
    		soc.send(message.encode("utf8"))
    		print("Closing the client. Thanks!")
    		soc.close()
    		sys.exit()
    	continue

if __name__ == "__main__":

	client_connect()