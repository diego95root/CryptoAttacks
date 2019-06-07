import sys, random
from DiffieHellman import *
from MT19937 import *
from AES import generateKey, decryptAES_CBC, encryptAES_CBC, PKCS7
from SHA1 import *

class DHProtocol():

    def __init__(self, p, g):
        self.p = p
        self.g = g
        self.ab = MT19937(random.randint(0, p)).getNumber()
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

    p = 0xffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff
    g = 2

    clientA = DHProtocol(p, g)
    clientB = DHProtocol(p, g)

    A = clientA.getAB()
    B = clientB.getAB()

    clientB.calculateKey(A)
    clientA.calculateKey(B)

    msg = "Hello DH key exchange"

    assert clientA.decrypt(clientB.encrypt(msg)) == clientB.decrypt(clientA.encrypt(msg))

    ###### MITM attack -> A/B = p ######

    clientA = DHProtocol(p, g)
    clientB = DHProtocol(p, g)

    clientB.calculateKey(p)
    clientA.calculateKey(p)

    msg = "Hello DH MITM attack"

    encB = clientB.encrypt(msg)
    assert decryptAES_CBC(encB[:-32], sha1("0")[:16], encB[-32:]) == PKCS7(msg, 16)

    # the previous thing works because passing p as A/B makes the modexp be 0 and so key is sha("0")

    ###### MITM attack -> g = p ######

    clientA = DHProtocol(p, g)
    clientB = DHProtocol(p, p)

    A = clientA.getAB()
    B = clientB.getAB()

    clientB.calculateKey(A)
    clientA.calculateKey(B)

    msg = "Setting g of the second person makes it possible to decrypt messages from the first one"

    encA = clientA.encrypt(msg)
    assert decryptAES_CBC(encA[:-32], sha1("0")[:16], encA[-32:]) == PKCS7(msg, 16)

    ###### MITM attack -> g = 1 ######

    clientA = DHProtocol(p, g)
    clientB = DHProtocol(p, 1)

    A = clientA.getAB()
    B = clientB.getAB()

    clientB.calculateKey(A) # if g = 1 key will always be sha("1")
    clientA.calculateKey(B)

    msg = "Setting g of the second person makes it possible to decrypt messages from the first one"

    encA = clientA.encrypt(msg)
    assert decryptAES_CBC(encA[:-32], sha1("1")[:16], encA[-32:]) == PKCS7(msg, 16)

    ###### MITM attack -> g = p - 1 ######

    clientA = DHProtocol(p, g)
    clientB = DHProtocol(p, p - 1)

    A = clientA.getAB()
    B = clientB.getAB()

    clientB.calculateKey(A)
    clientA.calculateKey(B)

    msg = "Setting g of the second person makes it possible to decrypt messages from the first one"

    encA = clientA.encrypt(msg)

    assert decryptAES_CBC(encA[:-32], sha1("1")[:16], encA[-32:]) == PKCS7(msg, 16) or decryptAES_CBC(encA[:-32], sha1(str(p-1))[:16], encA[-32:]) == PKCS7(msg, 16)
