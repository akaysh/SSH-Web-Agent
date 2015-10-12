from imports import *

# global variable B
B = 0

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
def verifySignature(pkey, signature, data):
    # Recreates the public key in required format
    pkey = "-----BEGIN PUBLIC KEY-----\n" + pkey + "-----END PUBLIC KEY-----"

    # Recreates the signature as a tuple
    signature = ast.literal_eval(signature)

    # Generates the hash of data
    hash = SHA256.new(data).digest()

    # Instantiates an object of type _RSAobj which is used for verification of signature
    key = RSA.importKey(pkey)

    # Verify if the session_data was actually signed by the trusted server
    return key.verify(hash, signature)

def compute_secret(p, g, A):
    # Object of class DiffieHellman
    dh = DiffieHellman()

    p = long(p)
    g = long(g)
    A = long(A)

    # Private key for agent
    b = dh.privateKey

    global B
    B = pow(g, b, p)

    # Secret = (A**b)%p
    return pow(A, b, p)

def compute_shared_secret(method, referer, e, f, S):
    data = method + referer + str(e) + str(f) + str(S)

    return SHA256.new(data).digest()

def compute_hash(S, shared_secret, identifier, referer):
    data = str(S) + shared_secret + identifier + referer

    return SHA256.new(data).digest()

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

    # identifier(same as mentioned in message_body)
    idx = identifier

    # payload
    # *************TBD**************
    # empty for message of type NEW
    payload = ''

    # padding
    # needed to meet the block size requirements of encryption algorithm
    padding = ''

    # Generate string for encryption
    plaintext = str(r) + str(type_of) + str(identifier) + str(payload) + str(padding)

    # Secret generated via DH key exchange
    secret = compute_secret(parameters['p'], parameters['g'], parameters['e'])

    # Shared secret computation
    method = 'POST'
    referer = '127.0.0.1'
    # e refers to 'A'
    e = parameters['e']
    f = B
    S = secret

    # secret computed via DH key exchange
    shared_secret = compute_shared_secret(method, referer, e, f, S)

    # key for AES_CBC mode
    secret_key = compute_hash(S, shared_secret, 'A', referer)

    # Taking first 16 bytes, since iv needs to be 16 bytes in length
    initialization_vector = compute_hash(S, shared_secret, 'B', referer)[0:16]

    # Ciphertext to be sent via HTTP
    ciphertext = AES.new(secret_key, AES.MODE_CBC, initialization_vector)

    # ========================================================================


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

def session_response(parameters):
    # Initialize a message template
    response_message = message()

    # Add request type
    response_message = request(response_message, 'KEX_DH_RESPONSE')

    # Add computed value of trusted server
    response_message['f'] = trusted_server()

    # Message body of type `NEW`
    response_message['E'] = generate_NEW_message_body(parameters)


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

class ClientThread(threading.Thread):

    def __init__(self, ip, port, socket):
        threading.Thread.__init__(self)
        self.ip = ip
        self.port = port
        self.socket = socket
        print "[+] New thread started for "+ip+":"+str(port)

    def run(self):
        print "Connection from: "+ ip + ":" + str(port)
        data = self.socket.recv(10240).strip()
        message = json.loads(data)
        messageType = message['type']

        # KEY_DH_REQUEST 0x02
        if messageType == 2:
            # Parse data using delimiter as `~`
            packet_data = message["data"].split("~")

            # parameters now has all the data from the packet
            parameters = get_params(packet_data)

            # Checks if the ip and publicKey are trusted
            if isTrusted(parameters['k'], ip):
                print "Trusted!"
                # Verifies authenticity using signature verification
                if verifySignature(parameters['k'], parameters['sign'], parameters['d']):
                    print "Verfied!"

                    # Generate a response message
                    response_message = session_response(parameters)

if __name__ == "__main__":
    # Declare host and port
    host = "0.0.0.0"
    port = 8008

    tcpsock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    tcpsock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    tcpsock.bind((host, port))

    # Threading for multiple clients
    threads = []

    while True:
        tcpsock.listen(4)
        print "\n[+] Listening for incoming connections..."
        (clientsock, (ip, port)) = tcpsock.accept()
        newThread = ClientThread(ip, port, clientsock)
        newThread.start()
        threads.append(newThread)

    # Join all threads
    for t in threads:
        t.join()
