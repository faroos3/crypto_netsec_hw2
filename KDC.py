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


id_list = {} # dictionary to keep track of which clients have connected or not
# the id_list is public as the threads can keep track of who has connected

shared_key_list = {} # dict to keep track of Diffie-Hellman results 
# I'm under the assumption the KDC is hosted somewhere on a secure server 
# This is a global so the KDC can see who already has a shared key between itself

# this function takes as input g, a, b, and n and returns 
# what the key will be in bit form 

def generate_b_for_clients():
	return random.randint(1, n)

def diffie_hellman(n, g, num_from_client, b):
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

# wrapper function that uses my toy_des functions
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

    soc.listen(5)       # queue up to 5 requests
    print("KDC now listening for connections...")

    ######################### Input my crypto stuff 

    Ks = generate_session_key()
    # print("The session key is going to be", Ks)

    ##########################

    # infinite loop- do not reset for every requests
    while True:
        connection, address = soc.accept()
        ip, port = str(address[0]), str(address[1])
        print("Connected with " + ip + ":" + port)

        try:
        	# write my own client_thread to handle allllll my crypto code 
            Thread(target=client_thread, args=(connection, ip, port, Ks)).start()
        except:
            print("Thread did not start.")
            traceback.print_exc()

    soc.close()

# 
def client_thread(connection, ip, port, Ks, max_buffer_size = 5120): 
	# this should be different if it's their first time connecting
	# versus their second time connecting. 
	print("New connection!\n")
	is_active = True 
	intitial_message = connection.recv(max_buffer_size)
	intitial_message_len = sys.getsizeof(intitial_message)
	decoded_initial_msg = intitial_message.decode("utf8").rstrip()
	# print("The initial message, which should be the client's ID, is:", decoded_initial_msg) # ADDING THE STRING B/C IT SENDS SOME RANDOM 4 NUMS FOR SOME REASON

	cli_ID = decoded_initial_msg[0:10]

	if len(cli_ID) < 10: 
		print("error with the cli_ID")
		return

	if cli_ID in id_list:
		id_list[cli_ID] += 1
		print("The client with ID", cli_ID, "has connected", id_list[cli_ID], "times.")
	else:
		id_list[cli_ID] = 1
		print("The client with ID", cli_ID, "has connected", id_list[cli_ID], "time.")
	# print("\nThe id_list is currently:", id_list, "\n")

	# if someone connected for the first time, need to do Diffie-Hellman to get a shraed key 
	if id_list[cli_ID] == 1:
		print("The KDC is now going to intitiate Diffie-Hellman to make a shared key with " + cli_ID + ".")
		b = generate_b_for_clients()
		to_send_to_a = str((g**b) % n)
		# connection.sendto()
		connection.send(to_send_to_a.encode("utf8"))
		recv_from_a = (connection.recv(max_buffer_size)).decode("utf8")
		# print("I RECEIVED THIS FROM THE CLIENT: ", recv_from_a)
		# print("I got", recv_from_a, "which has type:", type(recv_from_a))
		K_with_cli = ((int (recv_from_a))**b) % n
		# print("The shared key with the client", cli_ID, "is:", K_with_cli, "which as 10 bits is: {:010b}".format(K_with_cli))
		shared_key_list[cli_ID] = (K_with_cli, "{:010b}".format(K_with_cli))
		# print("Client", cli_ID, "has shared key:", shared_key_list[cli_ID])
		print("Closing the connection with", cli_ID, "as they have performed Diffie-Hellman.")
		connection.close()
	else:
		# The client is now going to ask the KDC for requests. 3 are supported - list, talk to, and quit. 
		is_needy = True # this is a flag to see if the client needs anything from the server
		while is_needy:
			print("I am now waiting for options from client", cli_ID + "...")
			command = (connection.recv(max_buffer_size)).decode("utf8")
			print("I received the command", command, "from client", cli_ID)
			# the list command 
			if(command == 'list'):
				list_to_send = "The clients that have connected are: "
				for client_ID in shared_key_list.keys():
					list_to_send += client_ID + " & "
				length_to_send = len(list_to_send) - 2
				list_to_send = list_to_send[0:length_to_send]
				connection.send(list_to_send.encode("utf8"))
			elif(command == "talk"):
				print("N-S initiated.")
				# n_s_start = "Please submit a client_ID that you'd like to talk to."
				# connection.send(n_s_start.encode("utf8"))
				# now wait for a response 
				client_desired = (connection.recv(max_buffer_size)).decode("utf8")
				if client_desired not in shared_key_list: # BAD CASE 
					print("Client", cli_ID, "wants to talk to someone who doesn't have a key with me and that's not allowed!")
					connection.send("ERROR: You have sent a client I have not spoken with. Try again!".encode("utf8"))
					continue
				else: # GOOD CASE: continue with step 1 
					# STEP 1 
					connection.send("We're good to go! Please send your first envelope of information.".encode("utf8"))
					# print("Now waiting on ID_a || ID_b || N_1 from the client.")
					first_envelope = (connection.recv(max_buffer_size)).decode("utf8")
					# print("Client ID", cli_ID, "sent the envelope:", first_envelope)
					# really only needed for the nonce 
					nonce = first_envelope[20:30] # as a 10bit string 
					# print("nonce received is:", nonce)
					# END STEP 1 

					# Start STEP 2 
					# now I need to use my toy_des stuff, and we're also going to use Ks.
					# first create the Ks || ID_A || Nonce 
					to_encr_with_Kb = Ks + ID_A + nonce
					# print("SHARED LIST KEY OF CLIENT DESIRED IS:", shared_key_list[client_desired][1])
					second_half_envelope_2 = encryptor(to_encr_with_Kb, shared_key_list[client_desired][1])
					# they're all strings so they should concatenate easily 
					second_env_to_encrypt = Ks + ID_B + nonce + second_half_envelope_2
					encryped_second_envelope = encryptor(second_env_to_encrypt, shared_key_list[cli_ID][1])
					print("The encrypyed second envelope I am sending to", cli_ID, "is", encryped_second_envelope)
					connection.send(encryped_second_envelope.encode("utf8"))
					# END STEP 2
			elif(command == "quit"):
				print("The client", cli_ID, "doesn't need the KDC anymore!")
				# del id_list[cli_ID]
				# del shared_key_list[cli_ID]
				is_needy = False
			else:
				print("Something went terribly wrong. Try again!")

		connection.close()

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