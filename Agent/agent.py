from imports import *


# global variable B
B = None
b = None
publicKey = None
signature = None
ips = []

# Checks if the IP and the referer are present in the trusted servers file
def isTrusted(pkey, referer):
    allowed_referers = []

    # Open trusted servers file for checking existence of ip and public key
    lines = open('./trusted.txt', 'r').read().split('\n')

    # Remove all `newlines` from public key arriving in packet
    p = pkey.replace('\n', '')

    for idx, line in enumerate(lines):
        pos = idx
        if line == p:
            while lines[pos] != '.':
                pos += 1
                allowed_referers.append(lines[pos])
            if referer in allowed_referers:
                # Referer found!
                return True
            else:
                return False
    return False

# Verifies the signature sent by the trusted server
def verifySignature(pkey, sig, data):
    # Recreates the public key in required format
    global publicKey, signature
    
    pkey = "-----BEGIN PUBLIC KEY-----\n" + pkey + "-----END PUBLIC KEY-----"

    # Recreates the signature as a tuple
    signature = ast.literal_eval(sig)

    # Setting global variables
    publicKey = pkey

    # Generates the hash of data
    hash = SHA256.new(data).digest()

    # Instantiates an object of type _RSAobj which is used for verification of signature
    key = RSA.importKey(pkey)

    # Verify if the session_data was actually signed by the trusted server
    return key.verify(hash, signature)

def compute_secret(p, g, A):
    # Object of class DiffieHellman
    dh = DiffieHellman()

    global B, b

    p = long(p)
    g = long(g)
    A = long(A)

    # Private key for agent
    b = dh.privateKey

    B = pow(g, b, p)

    # Secret = (A**b)%p
    return pow(A, b, p)

def generate_ciphertext(parameters, identifier):
    # Format of unencrypted text
    # byte[4] random
    # byte type
    # string identifier
    # -------payload---------
    # byte[n] padding

    # Random number of 128 bit size
    r = random.getrandbits(128)

    # type of request to be made.
    # NEW 0x02
    type_of = 0x02

    # payload
    # *************TBD**************
    # empty for message of type NEW
    payload = ''

    # Generate string for encryption
    plaintext = str(r) + str(type_of) + str(identifier) + str(payload)
    
    # Add padding block for making block size a multiple of 16 for encryption
    plaintext = add_padding(plaintext)

    # Secret generated via DH key exchange
    secret = compute_secret(parameters['p'], parameters['g'], parameters['e'])

    # Shared secret computation
    method = 'POST'
    referer = '127.0.0.1'
    # e refers to 'A'
    e = parameters['e']
    f = B
    S = secret

    # shared secret
    shared_secret = compute_shared_secret(method, referer, e, f, S)

    # key for AES_CBC mode
    secret_key = compute_hash(S, shared_secret, 'A', referer)

    # Taking first 16 bytes, since iv needs to be 16 bytes in length
    initialization_vector = compute_hash(S, shared_secret, 'B', referer)[0:16]

    # AES object for encryption of data to be sent via HTTP
    aes = AES.new(secret_key, AES.MODE_CBC, initialization_vector)

    # Ciphertext
    ciphertext = aes.encrypt(plaintext)

    return base64.b64encode(ciphertext)

def generate_NEW_message_body(parameters):
    # Format
    # byte algorithm (AES_256_CBC 0x02)
    # string identifier (session_identifier)
    # string ciphertext (encrypted part of the message body)

    message_body = dict()

    # Specifies the type of algorithm to be used for encryption
    # AES_256_CBC 0x02
    message_body['algorithm'] = 0x02

    # Session identifier set by agent.
    # ******** TDB ***********************
    # identifier = generate_identifier()
    identifier = '1'
    message_body['session_identifier'] = identifier

    # Generate Ciphertext
    message_body['ciphertext'] = generate_ciphertext(parameters, identifier)

    return message_body

def session_response(parameters):
    # Initialize a message template
    response_message = message()

    # Add request type
    response_message = request(response_message, 'KEX_DH_RESPONSE')

    # Message body of type `NEW`
    response_message['E'] = generate_NEW_message_body(parameters)

    # Add computed value of trusted server
    response_message['f'] = B
    
    return response_message

def generate_PRIVATE_message_body():
    # Format
    # byte[4] random
    # byte AUTH_RESPONSE
    # string identifier
    # boolean status
    # string signatures
    # string options
    # byte[n] padding

    r = random.getrandbits(128)

    # type of request to be made.
    # AUTH_RESPONSE 0x04
    type_of = 0x04

    # identifier
    identifier = 1
    #status to indicate signing process sucess or faliure
    status = True
    #signatures contains one or more signatures uint32+string[n]
    comment = 'comment'

    signatures = '1~'+'~'+str(publicKey)+'~'+str(signature[0])+'~'+comment
    # print publicKey
    # pass inforemation to the trusted server in the form of key value pairs
    # value should be encrypted with scheme es
    # here p key is public key of the client and key is the public key of the server (here same)
    
    pkey = RSA.importKey(publicKey)

    key = PKCS1_OAEP.new(pkey)
    value = 'value'
    value = key.encrypt(value)
    option = publicKey + '~' + str(base64.b64encode(value))
    options = '1~' + 'es~' + '~' + option

    # padding = 
    return options

def authentication_response():
    # Initialise a message template
    response_message = message()

    # Add request type
    response_message = request(response_message, 'PRIVATE')

    # Message body of type `PRIVATE`
    response_message['data'] = generate_PRIVATE_message_body()

    return response_message

# Returns all packet parameters
def get_params(params):
    parameters = dict()
    # large prime
    parameters['p']    = params[0]
    # generator for DH
    parameters['g']    = params[1]
    # computed value of trusted server in key exchange
    parameters['e']    = params[2]
    # session data(if any)
    parameters['d']    = params[3]
    # public key of the trusted server
    parameters['k']    = params[4]
    # signature to verify server identity
    parameters['sign'] = params[5]

    return parameters

def send(message):
    # Data transfer via HTTP Request(s)
    source_ip = '127.0.0.1'
    tcp_port = "8009"
    address = "http://" + source_ip + ":" + tcp_port
    requestData = json.dumps(message)

    try:
        r = requests.post(address, data = requestData, timeout=0.001)
    except:
        print "[+] Sent Data."

def wait():
    server = HTTPServer(('localhost', 8008), PostHandler)
    server.serve_forever()

class PostHandler(BaseHTTPRequestHandler):
    
    def do_POST(self):
        # Parse the form data posted
        form = cgi.FieldStorage(
            fp=self.rfile, 
            headers=self.headers,
            environ={'REQUEST_METHOD':'POST',
                     'CONTENT_TYPE':self.headers['Content-Type'],
                     })
        # Begin the response
        self.send_response(200)
        self.send_header('Content-Type', 'text/plain')
        self.end_headers()

        messageType = int(form['type'].value)
        message = form['data'].value
        requesterIP = self.headers['Host'].split(':')[0]

        if messageType == 2:
            # Parse data using delimiter as `~`
            packet_data = message.split("~")

            # parameters now has all the data from the packet
            parameters = get_params(packet_data)

            # Checks if the ip and publicKey are trusted
            if isTrusted(parameters['k'], requesterIP):
                print "Trusted!"
                # Verifies authenticity using signature verification
                if verifySignature(parameters['k'], parameters['sign'], parameters['d']):
                    print "Verified!"

                    # Generate a response message
                    response_message = session_response(parameters)
                    # print response_message
                    self.wfile.write(response_message)
                else:
                    error_message = dict()
                    error_message['message'] = "Signature not verified."
                    error_message['type'] = 0x1337
                    self.wfile.write(error_message)
            else:
                error_message = dict()
                error_message['message'] = "Not Trusted."
                error_message['type'] = 0x1337                
                self.wfile.write(error_message)                
        else:
            self.wfile.write(authentication_response())

        return

if __name__ == "__main__":

    wait()