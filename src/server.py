from imports import *

# Add message identification
def identify(session_message):
	session_message['id'] = "SSHWebAgent"
	return session_message

# Add message version
def version(session_message):
	# VERSION_1_1 (0x11)
	session_message['version'] = 0x11
	return session_message

# Add request type
def request(session_message):
	# KEX_DH_REQUEST = 0x02
	session_message['type'] = 0x02
	return session_message

# Diffie-Hellman key exchange parameters
def diffie_hellman():
	# dh is an object of type `DiffieHellman` 
	dh = DiffieHellman()

	# Server and client agree to use modulus p and base g
	# A->B
	# A chooses a secret integer(a.privateKey) and calculates A = (g**a)%p (here a.publicKey)
	p = dh.prime
	g = dh.generator

	return 	p,g

# Returns computed value of trusted server in key exchange
def trusted_server():
	return 'default'

# Returns session_data if any added by trusted server, It shall be used by SSH-WebAgent without interpretation
def session_data():
	return 'default_data'

# Returns publicKey and signature to be sent to the trusted server
def signature(data):
	# Key, Signature parameters for RSA. 
	# Create a new pair for every connection?
	key = RSA.generate(1024)
	
	# Write keys to file
	pubKey = key.publickey().exportKey()
	privKey = key.exportKey()

	f = open('../.ssh/id_rsa.pub','w')
	f.write(pubKey)
	f.close()

	f = open('../.ssh/id_rsa', 'w')
	f.write(privKey)
	f.close()

	# Sign the session data
	h = SHA256.new(d).digest()

	# Random number k
	k = random.StrongRandom().randint(1, key.q-1)
	signature = key.sign(h,'')

	return k, signature


if __name__ == "__main__":
	# Declare a session message variable to be sent as json
	session_message = {}

	# Add id
	session_message = identify(session_message)

	# Add versioning
	session_message = version(session_message)

	# Add request type
	session_message = request(session_message)

	# Generate diffie_hellman key exchange parameters
	p,g = diffie_hellman()

	# Computed value of trusted server in key-exchange
	e = trusted_server()

	# Session data
	d = session_data()

	# Add to message
	session_message['data'] = d

	# Get key and signature
	k, sign = signature(d)

	# Socket-based transfer of data
	source_ip = '127.0.0.1'
	tcp_port = 8008
	packet = json.dumps(session_message)

	'''
	TBD
	===

	try:
		s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	except:
		print 'Socket cannot be created.'
		sys.exit()

	s.connect((source_ip, tcp_port))
	s.send(packet)
	s.close()

	print "[*] Sent Data."

	'''
