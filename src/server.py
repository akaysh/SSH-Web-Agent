from imports import *

# global variable dh_key
A = 0

# Diffie-Hellman key exchange parameters
def diffie_hellman():
	# dh is an object of type `DiffieHellman`
	dh = DiffieHellman()

	# Server and client agree to use modulus p and base g
	# A->B
	# A chooses a secret integer(dh.privateKey) and calculates A = (g**dh.privateKey)%p (here a.publicKey)
	p = dh.prime
	g = dh.generator

	global A
	A = dh.publicKey

	return	p,g

# Returns session_data if any added by trusted server, It shall be used by SSH-WebAgent without interpretation
def session_data():
	return 'default_data'

# Returns publicKey and signature to be sent to the trusted server
def signature(data):
	# Key, Signature parameters for RSA.

	# Signing the message with private key
	f = open('../.ssh/id_rsa', 'r')
	key = RSA.importKey(f.read())
	f.close()

	# Sign the session data
	h = SHA256.new(data).digest()

	# Signature
	signature = key.sign(h,'')

	# Public Key
	pubKey = open('../.ssh/id_rsa.pub').read()

	# Strip first and last lines of the public key(format)
	pubKey = pubKey.strip("-----BEGIN PUBLIC KEY-----\n").strip("-----END PUBLIC KEY-----")

	return pubKey, signature

def session_request():
	# Create a message template
	request_message = message()

	# Add request type
	request_message = request(request_message, 'KEX_DH_REQUEST')

	# Generate diffie_hellman key exchange parameters
	p,g = diffie_hellman()

	# Computed value of trusted server in key-exchange
	e = A

	# Session data
	d = session_data()

	# Get key and signature
	k, sign = signature(d)

	# Use ~ as delimiter for data parameters
	request_message['data'] = ""
	request_message['data'] += str(p)
	request_message['data'] += '~' + str(g)

	request_message['data'] += '~' + str(e)
	request_message['data'] += '~' + str(d)
	request_message['data'] += '~' + str(k)
	request_message['data'] += '~' + str(sign)

	return request_message

if __name__ == "__main__":

	# Socket-based transfer of data
	source_ip = '127.0.0.1'
	tcp_port = 8008
	request_packet = json.dumps(session_request())

	try:
		s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	except:
		print 'Socket cannot be created.'
		sys.exit()

	try:
		s.connect((source_ip, tcp_port))
	except:
		print "Host not up! Exiting..."
		sys.exit()
	s.send(request_packet)
	s.close()

	print "[+] Sent Data."
