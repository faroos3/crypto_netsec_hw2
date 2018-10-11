'''
This is the file that contains the Diffie-Hellman algorithm to establish shared keys between Alice, Bob, and the KDC. It'll just be functions that are going 
to be used in other files. 

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

import random # want to use random.randint(1, n) 
import time
import toy_des

# these are in the public domain of Diffie-Hellman
g = 331 
n = 1021

def key_maker():
	


if __name__ == "__main__":