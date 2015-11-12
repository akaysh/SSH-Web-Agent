from imports import *


# Add padding to plaintext to make length same as block size of AES_CBC_256 mode
def add_padding(plaintext):
    l = len(plaintext)
    i = 16

    while l > i:
        i += 16

    return plaintext + '0'*(i-l)

# Compute shared secret between server and agent
def compute_shared_secret(method, referer, e, f, S):
    data = method + referer + str(e) + str(f) + str(S)

    return SHA256.new(data).digest()

# Compute hash of elements passed to the function
def compute_hash(S, shared_secret, identifier, referer):
    data = str(S) + shared_secret + identifier + referer

    return SHA256.new(data).digest()

# Add message identification
def identify(session_message):
	session_message['id'] = "SSHWebAgent"
	return session_message

# Add message version
def version(session_message):
	# VERSION_1_1 (0x11)
	session_message['version'] = 0x11
	return session_message

# Returns computed value of trusted server in key exchange
def trusted_server():
	return 'default'	

# Add request type
def request(session_message, request_type):
	if request_type == 'KEX_DH_REQUEST':	
		# KEX_DH_REQUEST 0x02
		session_message['type'] = 0x02
	
	elif request_type == 'KEX_DH_RESPONSE':
		# KEX_DH_RESPONSE 0x03
		session_message['type'] = 0x03

	elif request_type == 'PRIVATE':
		# PRIVATE 0x04
		session_message['type'] = 0x04

	return session_message

def message():
	message = dict()

	message = identify(message)
	message = version(message)

	return message
