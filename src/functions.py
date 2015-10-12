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
		return session_message
	
	elif request_type == 'KEX_DH_RESPONSE':
		
		# KEX_DH_RESPONSE 0x03
		session_message['type'] = 0x03
		return session_message

def message():
	message = dict()

	message = identify(message)
	message = version(message)

	return message	
