from imports import *


# A and a refer to DH public and private key respectively
A = 0
a = 0
# DH prime
p = 0
ips = []

def send(message):
	# Data transfer via HTTP Request(s)
	source_ip = '127.0.0.1'
	tcp_port = "8010"
	address = "http://127.0.0.1:8008"
	headers = {"content-type": "application/x-www-form-urlencoded"}
	# requestData = json.dumps(message)

	req = requests.post(address, data = message, headers=headers)
	message = ast.literal_eval(req.content)

	if message['type'] == 0x3:
		authentication_request(message)
	elif message['type'] == 0x4:
		print '[+] Received authentication response'

# Diffie-Hellman key exchange parameters
def diffie_hellman():
	# dh is an object of type `DiffieHellman`
	dh = DiffieHellman()

	global A, a, p
	# Server and client agree to use modulus p and base g
	# A->B
	# A chooses a secret integer(dh.privateKey) and calculates A = (g**dh.privateKey)%p (here a.publicKey)
	p = dh.prime
	g = dh.generator

	A = dh.publicKey
	a = dh.privateKey

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

def compute_secret(p, B):
	# Secret = (B**a)%p
	return pow(B, a, p)

def generate_ciphertext(shared_secret, secret_key, initialization_vector, identifier):
	# Format
	# byte[4] random
	# byte AUTH_REQUEST
	# string identifier
	# string SSH session identifier
	# byte[n] padding

    # Random number of 128 bit size
    r = random.getrandbits(128)

    # type of request to be made.
    # AUTH_REQUEST 0x03
    type_of = 0x03

    # SSH Session identifier
    # As per RFC4253, The exchange hash H from the first key exchange is additionally used as the session identifier, which is a unique identifier for this connection
    SSH_session_identifier = shared_secret

    # Generate string for encryption
    plaintext = str(r) + str(type_of) + str(identifier) + str(SSH_session_identifier)

    # Add padding to plaintext since block size of AES_CBC_256 mode is 16
    plaintext = add_padding(plaintext)

    # Create an AES object
    aes = AES.new(secret_key, AES.MODE_CBC, initialization_vector)
    
    # Ciphertext
    ciphertext = aes.encrypt(plaintext)

    return base64.b64encode(ciphertext)
 
def generate_AUTH_REQUEST_message_body(shared_secret, secret_key, initialization_vector):
	# Format
	# byte algorithm (AES_256_CBC 0x02)
	# string identifier (session_identifier)
	# string ciphertext (encrypted part of message body)

	message_body = ''

    # Specifies the type of algorithm to be used for encryption
    # AES_256_CBC 0x02
	message_body+= '0x02~'

    # Session identifier set by agent.
    # ******** TDB *********************
    # identifier = generate_identifier()
	identifier = '1'
	message_body += identifier+'~'

    # Generate Ciphertext
	message_body += generate_ciphertext(shared_secret, secret_key, initialization_vector, identifier)

	return message_body

def authentication_request(data):	
	# Shared secret computation
	method = 'POST'
	referer = '127.0.0.1'
	# e refers to 'A'
	e = A
	# Diffie Hellman public key of agent
	# f refers to 'B'
	f = data['f']
	# print f
	# secret key computed via DH key exchange
	S = compute_secret(p, f)

	# shared secret
	shared_secret = compute_shared_secret(method, referer, e, f, S)

	# key for AES_CBC mode
	secret_key = compute_hash(S, shared_secret, 'A', referer)

    # Taking first 16 bytes, since iv needs to be 16 bytes in length
	initialization_vector = compute_hash(S, shared_secret, 'B', referer)[0:16]

    # AES object for encryption of data to be sent via HTTP
	aes = AES.new(secret_key, AES.MODE_CBC, initialization_vector)

    # received ciphertext
	ciphertext = base64.b64decode(data['E']['ciphertext'])

    # Plaintext obtained through AES decryption
	plaintext = aes.decrypt(ciphertext)

	# Acknowledge decryption of ciphertext
	print "[+] Received plaintext!"

	# Generate a message with version number and id
	auth_message = message()

	# add message request type
	auth_message = request(auth_message, 'PRIVATE')

	# message_body
	auth_message['data'] = generate_AUTH_REQUEST_message_body(shared_secret, secret_key, initialization_vector)


	send(auth_message)

if __name__ == "__main__":

	send(session_request())
	# wait()