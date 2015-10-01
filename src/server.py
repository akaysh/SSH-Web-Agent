import socket, random, sys, json
from message import Message

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


session_message['type'] = request()

# p,e,g,k,d

# Diffie-Hellman key exchange parameters
a = 10
b = 1000

p = random.choice([i for i in cached_primes if a<i<b])
print p

g = 2

# Computed value
e = 'default_session'

# Empty session data
d = ''

# Key, Signature parameters
k = 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQCk38MafOpY4mXqDZ6+oIyXm1hblk6p1RO9c7750jL5x09+RzSW46WGFnrgqAL51gKNCpT1MqCrZtLiA5SzbT7NaQQfMywY7mxT1p5xsd2aKdRI9DgAoRuB+VXVWSfMflgf7bZuTr6HnMeiBZ9ucu/2T5QzMszHcHJ9qhUDBS4VUyWEWftGZumQrre3/K8DOIEAK2YnCYxKJsZFlUYvgtDRh+7wlBwVASZh/OK0MMfFQtpmcLrmMaLGp4P+gO8hP1MaECQVE3dEGYeBvvD8fJa0UY52DnfOHI4THPlevegGoX04eEqQ3pCRCHP5nbRZruEkh6+DVFXdLOSlSpnVuribXbBiKp7alYGjlnYbgcW0wqY0JQ9dC5DC0ydusrU6MeJd3vx2NzyIu03RCwx2nPQHLPIJiY+gTiQky0Znz/FCB0X71xtexgSfapU/g3EBWYaNYy96C5hzAWZRReWlDLJVfv0ja7KVv4LVcU4wo7lgMWDfStOyPfSAkaTHlD9wMo2UjR7jXK6ykE0a2ym/vJ79anFU0k6hnKmox+rjhRrk40O3Lh2BkYa15yhnlPfJb9RBoPhMZVNA9QSkilHaFSVwUr8VxohTlCEnTETH/mMr2H6VjlPsapdbgvXfzKI1ExGQ3URmr94D951OCYG6E/qAt8hswdGZiB1dw5XtW/TjOw== chinmay1dd@gmail.com'
sign = 'signauture'

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
data += k + ';'
data += sign

# Empty tuple
session_message['data'] = data

source_ip = '127.0.0.1'
tcp_port = 8008
packet = json.dumps(session_message)

s.connect((source_ip, tcp_port))
s.send(packet)
s.close()

print "[*] Sent Data."