from imports import *


def isTrusted(pkey, referer):
    allowed_referers = []
    lines = open('./trusted.txt', 'r').read().split('\n')
    p = pkey.replace('\n', '')
    for idx, line in enumerate(lines):
        pos = idx
        if line == p:
            while lines[pos] != '.':
                pos += 1
                allowed_referers.append(lines[pos])
            if referer in allowed_referers:
                return True
            else:
                return False
    return False

def verifySignature(pkey, signature, data):
    pkey = "-----BEGIN PUBLIC KEY-----\n" + pkey + "-----END PUBLIC KEY-----"
    signature = ast.literal_eval(signature)

    hash = SHA256.new(data).digest()
    key = RSA.importKey(pkey)
    print signature, type(signature)

    return key.verify(hash, signature)



class ClientThread(threading.Thread):

    def __init__(self, ip, port, socket):
        threading.Thread.__init__(self)
        self.ip = ip
        self.port = port
        self.socket = socket
        print "[+] New thread started for "+ip+":"+str(port)

    def run(self):
        print "Connection from: "+ip+":"+str(port)
        data = self.socket.recv(10240).strip()
        message = json.loads(data)
        messageType = message['type']

        # KEY_DH_REQUEST
        if messageType == 2:
            parameters = dict()
            temp_params = message["data"].split("~")
            parameters['p'] = temp_params[0]
            parameters['g'] = temp_params[1]
            parameters['e'] = temp_params[2]
            parameters['d'] = temp_params[3]
            parameters['k'] = temp_params[4]
            parameters['sign'] = temp_params[5]

            if isTrusted(parameters['k'], ip):
                print "Trusted!"
                if verifySignature(parameters['k'], parameters['sign'], parameters['d']):
                    print "Verfied!"

        # print message

if __name__ == "__main__":
    host = "0.0.0.0"
    port = 8008

    tcpsock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    tcpsock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    tcpsock.bind((host, port))
    threads = []

    while True:
        tcpsock.listen(4)
        print "\nListening for incoming connections..."
        (clientsock, (ip, port)) = tcpsock.accept()
        newThread = ClientThread(ip, port, clientsock)
        newThread.start()
        threads.append(newThread)

    for t in threads:
        t.join()