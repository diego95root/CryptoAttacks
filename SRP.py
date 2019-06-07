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
        self.B = k * self.v + modexp(g, self.b, N)

    def sendOne(self):
        return (self.salt, self.B)

    def compute(self, I, A):

        uH = sha256(str(A) + str(self.B)).hexdigest()
        u = int(uH, 16)

        S = modexp(A * modexp(self.v, u, self.N), self.b, self.N)
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

    def compute(self, salt, B):

        uH = sha256(str(self.A) + str(B)).hexdigest()
        u = int(uH, 16)

        xH = sha256(salt + self.P).hexdigest()
        x = int(xH, 16)

        S = pow(B - self.k * modexp(self.g, x, self.N), self.a + u * x, self.N)
        self.K = sha256(str(S)).hexdigest()

    def sendHMAC_256(self, message):

        return HMAC_sha256(self.K, message)

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
    salt, B = server.sendOne()

    client.compute(salt, B)
    server.compute(I, A)

    # verify that HMAC_SHA256 is the same

    assert client.sendHMAC_256("message") == server.sendHMAC_256("message")
