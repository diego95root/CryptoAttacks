import sys, random
from DiffieHellman import *
from MT19937 import *
from AES import generateKey, decryptAES_CBC, encryptAES_CBC, PKCS7
from SHA1 import *

class DHProtocol():

    def __init__(self, p, g):
        self.p = p
        self.g = g
        self.ab = MT19937(random.randint(0, 100000)).getNumber() & 0xffff
        self.key = 0

    def getAB(self):
        return modexp(self.g, self.ab, self.p)

    def calculateKey(self, otherAorB):
        self.key = sha1(str(modexp(otherAorB, self.ab, self.p)))[:16]

    def encrypt(self, message):
        iv = generateKey(16).encode("hex")
        data = PKCS7(message, 16).encode("hex")
        return encryptAES_CBC(data, self.key, iv).encode("hex") + iv

    def decrypt(self, message):
        dec = decryptAES_CBC(message[:-32], self.key, message[-32:]).strip()
        return dec

if __name__ == "__main__":

    p = 123123 #raw_input("[*] Enter p: ")
    g = 456456 #raw_input("[*] Enter q: ")

    clientA = DHProtocol(p, g)
    clientB = DHProtocol(p, g)

    A = clientA.getAB()
    B = clientB.getAB()

    clientB.calculateKey(A)
    clientA.calculateKey(B)

    msg = "Hello DH key exchange"

    assert clientA.decrypt(clientB.encrypt(msg)) == clientB.decrypt(clientA.encrypt(msg))

    ###### MITM attack ######

    clientA = DHProtocol(p, g)
    clientB = DHProtocol(p, g)

    clientB.calculateKey(p)
    clientA.calculateKey(p)

    msg = "Hello DH MITM attack"

    encB = clientB.encrypt(msg)
    assert decryptAES_CBC(encB[:-32], sha1("0")[:16], encB[-32:]).strip() == msg

    # the previous thing works because passing p as A/B makes the modexp be 0 and so key is sha("0")
