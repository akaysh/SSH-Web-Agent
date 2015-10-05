import socket, random, sys, json
from message import Message
from Crypto.Random import random
from Crypto.PublicKey import DSA
from Crypto.Hash import SHA

def isPrime(p):
    if(p==2): return True
    if(not(p&1)): return False
    return pow(2,p-1,p)==1

def request():
	# KEX_DH_REQUEST = 0x02
	return 0x02

# initialising primes
minPrime = 10
maxPrime = 1000
cached_primes = [i for i in range(minPrime,maxPrime) if isPrime(i)]

# Creating a new object of type Message
session_message = {}
session_message['id'] = "SSHWebAgent"

# VERSION_1_1
session_message['version'] = '0x11'

# Request Type
session_message['type'] = request()

# p,e,g,k,d

# Diffie-Hellman key exchange parameters
a = 10
b = 1000

# Server and client agree to use modulus p and base g
p = random.choice([i for i in cached_primes if a<i<b])
# print p

# Using a default value for g
g = 2

# Key, Signature parameters
key = DSA.generate(1024)

# Let's sign the session data
h = SHA.new(d).digest()

# Random number k
k = random.StrongRandom().randint(1, key.q-1)
signature = key.sign(h,k)z

# Computed value of session variable
e = 'default_session'

# Empty session data
d = ''

try:
	s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
except:
	print 'Socket cannot be created.'
	sys.exit()

# Creating data string
data = ''
data += str(p) + ';'
data += str(b) + ';'
data += e + ';'
data += d + ';'
data += key + ';'
data += signature

# Empty tuple
session_message['data'] = data

source_ip = '127.0.0.1'
tcp_port = 8008
packet = json.dumps(session_message)

s.connect((source_ip, tcp_port))
s.send(packet)
s.close()

print "[*] Sent Data."