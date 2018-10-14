# CSCI 4320 HW2 PROGRAMMING PART

This is my submission for HW2 of CSCI 4320 taught by Professor Yener at RPI during the Fall 2018 term. It is a program consisting of three files. These files ultimately use the Diffie-Hellman key exchange algorithm to pass shared keys between themselves securely and then use the Needham-Schroeder algorithm to communicate securely. 

The first file is KDC.py, meant to model a Key Distribution Center. Clients can connect to it in order to secruely get a session key to use when connecting to each other. 
The second file is alice.py, meant to represent a user who is trying to communicate with another user. This client connects to KDC.py upon initialization and is the client that tries to initiate conversation.
The final file is bob.py, meant to represent another user who is trying to communicate with Alice. This client will also connect to the KDC, but then can also open up its own socket in order listen for another connection. 

## USAGE
In order to use these files properly and run a good test case, please follow the steps as shown:
1. Download all the files and put them in the same directory. Open up three terminal windows as three will be needed.
2. In one of the terminals, run the command "python3 KDC.py". This runs the KDC and gets it ready to accept clients.
3. In another terminal, run the command "python3 alice.py". This connects Alice to the KDC and establishes a shared key using Diffie-Hellman.
4. In the other unused terminal, run the command "python3 bob.py". This connects Bob to the KDC and establishes a shared key using Diffie-Hellman.
5. In the bob.py terminal, enter the "wait" option. This closes bob's connection to the KDC and has it set up its own socket for Alice to connect to.
6. In the alice.py terminal, enter the "talk" option. The client will then who you would like to talk to. One of the assumptions made based on what a mentor said at office hours was that IDs of clients are in the public space. Therefore, the user would then enter in Bob's ID, which is "0010010110". Please enter that ID!
7. The chatroom is now established between Alice and Bob! Alice sends messages, then Bob sends them. These messages are encrypted and decrypted with the shared key Ks that the KDC had generated (which is a new shared key every time KDC.py is ran). Send a message to Bob, then switch to the Bob terminal to view the message and send a response. 
8. To close the programs, send "QUIT" in whoever's turn it is to send a message. If you are in Alice's terminal, switch to Bob's terminal after sending quit and send one last message to Alice. The chat will end after that. If you are in Bob's terminal, Alice's terminal will end upon sending quit. You can then type in 'quit' in Bob's option to end the program. It ends in an error, which I am not sure how to fix, but the program closes anyway, so let us call it a feature.

You can also type "list" in either Alice or Bob before sending "talk" or "wait" to see who has connected with the client by seeing their IDs. 

## ASSUMPTIONS
There were multiple assumptions made when writing this program. The first assumption has to do with what is presented in the public domain. In all three files, the large prime number n is known as well as the smaller prime g that is used in the Diffie-Hellman key exchange. These are hardcoded and are public (represented by being global variables) as they are in the public space in real Diffie-Hellman exchanges. These numbers can also be represented by at most 10-bits because the toy_des likes 10-bit numbers. 

Another assumption made was that IDs for users are public. IDs are also 10 bits long as the toy_des likes to play with 10 bit numbers, and it is easier to do prove the concept with everything as 10-bits. Keys are also 10-bits as that is what HW1 required, which this HW uses in order to actually encrypt. 

An assumption was made regarding the host and port of Bob. This was done in order to prove the concept faster, and we operate under the assumption that Bob had given Alice the host and port information in another secure way before using these files. In the same field, it is assumed that Alice would be the one connecting to Bob and Bob would be the one to host. If so desired, these roles can be changed by moving code around. 

While not necessarily an assumption, global variables are used in the KDC.py to store the number of times an ID has connected to the KDC. The KDC also stores shared keys between its clients in a global dictionary. The KDC does operate under the assumption that a client connecting to the KDC for the first time would like a shared key, so it will run the Diffie-Hellman key exchange immedietly upon every new connection. 

One final assumption is that the nonces generated to prevent against replay attacks are randomly generated and are between 1 and n.

## ALGEBRAIC CONSTRUCTIONS / HOW IT WORKS
Again, this is a project that uses Computational Diffie-Hellman to distribute unique keys to clients, which clients can then use to share a session key (generated by the KDC) securety between themselves. 

It is important to note that whenever encryption or decryption are mentioned, the program is using a toy_des 8-bit block cipher developed in HW1 which uses 10-bit keys. 

Upon connecting to the KDC for the first time, a client generates a number between 1 and n to use as its private key. The KDC also generates a unique number between 1 and n to help with the Diffie-Hellman process. These numbers are used for the Diffie-Hellman key exchange algorithm as described by the slides and the video provided in the references column. G is raised to the power of a or b depending on where you are, modded by n, and then sent to the other person. That person raises that number to their private key, and mods it by n. This is the shared key the client and KDC will use between each other.

The KDC, Alice, and Bob then all perform the Needham-Schroeder protocol. This consists of 5 steps as provided in the slides. First, Alice sends the intent of wanting to talk to a user (Bob) and sends the KDC Alice's ID, Bob's ID, and a generated nonce all concatenated together to the KDC. Next, the KDC encrypts the generated session key, A's ID, and the provided nonce with Bob's session key. Then, the session key Ks, Bob's ID, and the same nonce from A is concatenated with the "envelope" which was just encrypted with Bob's session key. This is then encrypted with Alice's session key and sent to Alice. Next, Alice decrypts this large "envelope" in order to get the generated session key, and checks its nonce to make sure it was not tampered with. Alice disconnects from the KDC and connects to a waiting Bob in order to send the part of the envelope that was encrypted with Bob's session key. Next, Bob receives that envelope and decrypts it using the key it generated with the KDC. Now Bob has the session key generated from the KDC, and it never received it from the KDC directly! The following steps are done in order to ensure the key is legit - Bob generates its own nonce and encrypts it with the decrypted session key. Bob is going to send this to Alice and is expecting nonce - 1. Finally, Alice receives this encrypted nonce, decrypts it, subtracts one from the nonce, and sends it back to Bob. Bob receives the nonce minus one, and then sends a message saying Alice is ok to set up the chatroom. The chatroom then uses the session key for Alice and Bob to send messages to each other. If these nonces are messed up at any time, Bob will disconnect Alice from it because this may not be the Alice it is expecting. By using these nonces, the program prevents against replay attacks. 

Alice and Bob can securely send each other messages! 

## LESSONS LEARNED
The main lesson learned from this assignment was how Diffie-Hellman and Needham-Schroeder worked. The theory is very elegant and is fun to see in action. 

If I were to do this assignment again, I would obviously start earlier. Aside from that, the hardest part was definetly the debugging on the python socket programming. Remember to use send() and not sendall(), as I ran into errors trying to send information because sendall() was sending information I was not ready to process yet. Network programming should probably be a prerequisite for this class! 

Again, this homework was super cool to implement! Thanks for the help of the mentors/TA along the way! 

## REFERENCES
The following outside sources were used in order to understand the project better. 
* https://www.youtube.com/watch?v=Yjrfm_oRO0w - this video by computerphile really helped me understand Diffie-Hellman, and the terminology used in the video matches what is in the program. 
* https://kuntalchandra.wordpress.com/2017/08/23/python-socket-programming-server-client-application-using-threads/ - this code was used to help set up python network programming, especially the multi-clients to one server. The provided code is heavily modified in the final project. 

## LICENSE
This HW is fully open source and operates under the MIT License:
Copyright 2018 Samad Farooqui

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

However, if you are trying to implement your own D-H or N-S protocol, I encourage you to try and write it yourself as writing it is pretty fun :) 