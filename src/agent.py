from imports import *

# Checks if the IP and the referrer are present in the trusted servers file
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
                # Referrer found!
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

def session_response(parameters):
    # Initialize a message template
    response_message = message()

    # Add request type
    response_message = request_type(response_message, 'KEX_DH_RESPONSE')

    # Add computed value of trusted server
    response_message['f'] = trusted_server()

    # Message body of type `NEW`
    # ====
    # TBD
    # ====
    response_message['E'] = generate_response_message()


# Returns all packet parameters
def get_params(params):
    parameters = dict()
    parameters['p']    = params[0]
    parameters['g']    = params[1]
    parameters['e']    = params[2]
    parameters['d']    = params[3]
    parameters['k']    = params[4]
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