import random
from DiffieHellman import modexp
from hashlib import sha256
from MT19937 import *
from serverHMAC import HMAC_sha256

def randomNumber():
    rand1 = random.randint(0, 100000)
    rand2 = random.randint(1, 50)
    generator = MT19937(rand1)
    for i in range(rand2):
        number = generator.getNumber() # generate random salt
    return number

class Server():

    def __init__(self, P, g, k, N):

        self.salt = str(randomNumber())

        xH = sha256(self.salt + P).hexdigest()
        x = int(xH, 16)

        self.v = modexp(g, x, N)
        self.g = g
        self.N = N
        self.b = randomNumber()
        self.B = modexp(g, self.b, N)
        self.u = random.getrandbits(128)

    def sendOne(self):
        return (self.salt, self.B, self.u)

    def compute(self, I, A):

        S = modexp(A * modexp(self.v, self.u, self.N), self.b, self.N)

        self.K = sha256(str(S)).hexdigest()

    def sendHMAC_256(self, message):

        return HMAC_sha256(self.K, message)

class Client():

    def __init__(self, P, I, g, k, N):

        self.g = g
        self.k = k
        self.P = P
        self.N = N
        self.I = I
        self.a = randomNumber()
        self.A = modexp(g, self.a, N)

    def sendOne(self):
        return (self.I, self.A)

    def compute(self, salt, B, u):

        xH = sha256(salt + self.P).hexdigest()
        x = int(xH, 16)

        S = modexp(B, self.a + u * x, self.N)

        self.K = sha256(str(S)).hexdigest()

    def sendHMAC_256(self, message):

        return HMAC_sha256(self.K, message)

def bruteforceSRP(guess, hmac, salt, g, b, N, A, u):

    xH = sha256(salt + guess).hexdigest()
    x = int(xH, 16)

    v = modexp(g, x, N)
    S = modexp(A * modexp(v, u, N), b, N)
    K = sha256(str(S)).hexdigest()

    hmacTest = HMAC_sha256(K, "message")

    if hmacTest == hmac:
        return 1

    return 0

if __name__ == "__main__":

    # N is a large safe prime (N = 2q + 1, where q is prime)
    # openssl dhparam -text 1024

    N = 154145522410333960597140828701534027771472871986479740282387847744846891967763904740272173123964394098917444348538955113164074690456781360617971096550573442536512900842376853566712875338462231981536330469208218461954598658793053060828842150379342206447614716921554765208584383707254608755473148758857481554547
    g = 2
    k = 3
    I = "myemailiscool@gmail.com"
    P = "secretPassword"

    server = Server(P, g, k, N)
    client = Client(P, I, g, k, N)

    I, A = client.sendOne()
    salt, B, u = server.sendOne()

    client.compute(salt, B, u)
    server.compute(I, A)

    # verify that HMAC_SHA256 is the same

    clientHMAC = client.sendHMAC_256("message")
    serverHMAC = server.sendHMAC_256("message")

    if clientHMAC == serverHMAC:
        print "[*] OK, valid!"
    else:
        print "[*] Invalid password!"

    list = ["Nope", "Yes", "Secret?", "secretPassword"]

    for i in list:
        if bruteforceSRP(i, clientHMAC, salt, g, server.b, N, A, u):
            print "[*] Password is {}".format(i)
            break
