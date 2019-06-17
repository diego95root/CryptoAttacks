from DiffieHellman import modexp
from SHA1 import sha1
from Crypto.Util.number import bytes_to_long, long_to_bytes, getPrime
import gmpy
from MT19937 import MT19937
import time

def gcd(a, b):
    while b != 0:
        a, b = b, a % b
    return a

def getCoprimes(e):

    phi = 0

    while gcd(e, phi) != 1:
        p = getPrime(512)
        q = getPrime(512)
        phi = (p - 1) * (q - 1)

    return [p, q]

def egcd(a, b):
    if a == 0:
        return (b, 0, 1)
    else:
        g, y, x = egcd(b % a, a)
        return (g, x - (b // a) * y, y)

def modinv(a, m):
    g, x, y = egcd(a, m)
    if g != 1:
        raise Exception('modular inverse does not exist')
    else:
        return x % m

class RSA():

    def __init__(self, p, q, e):

        n = p * q
        phi = (p - 1) * (q - 1)
        d = modinv(e, phi)

        assert modinv(17, 3120) == 2753

        self.e = e
        self.n = n
        self.d = d

    def encrypt(self, data):

        return modexp(bytes_to_long(data), self.e, self.n)

    def decrypt(self, data):

        dec = modexp(data, self.d, self.n)

        return long_to_bytes(dec)

def broadcastAttack(c, n):

    m0 = n[1] * n[2]
    m1 = n[0] * n[2]
    m2 = n[0] * n[1]

    N = n[0] * n[1] * n[2]

    a = c[0] * m0 * modinv(m0, n[0])
    b = c[1] * m1 * modinv(m1, n[1])
    c = c[2] * m2 * modinv(m2, n[2])

    result = (a + b + c) % N

    return long_to_bytes(gmpy.mpz(result).root(3)[0])

class recoveryOracle():

    def __init__(self):

        self.decrypted = []
        self.e = 3
        p, q = getCoprimes(self.e)
        self.n = p * q
        self.rsa = RSA(p, q, self.e)

    def encrypt(self, data):

        return self.rsa.encrypt(data)

    def decrypt(self, data):

        hash = sha1(str(data))

        if hash in self.decrypted:
            return "[*] Error, hash already decrypted"

        self.decrypted.append(hash)
        return self.rsa.decrypt(data)

################ CHALLENGE FUNCTIONS ##########################

def rsaTest():

    e = 3
    p, q = getCoprimes(e)

    rsa = RSA(p, q, e)

    data = "HELLO RSA! How are you? HELLO RSA! How are you? HELLO RSA! How are you? HELLO RSA! How are you? HELLO RSA! How are you?"

    enc = rsa.encrypt(data)
    dec = rsa.decrypt(enc)

    assert dec == data

def broadcastTest():

    e = 3

    p1, q1 = getCoprimes(e)
    p2, q2 = getCoprimes(e)
    p3, q3 = getCoprimes(e)

    # string length no bigger than 128
    message = "HELLO THIS IS A SECRET TOP SECRET"

    r1 = RSA(p1, q1, e)
    r2 = RSA(p2, q2, e)
    r3 = RSA(p3, q3, e)

    c1 = r1.encrypt(message)
    c2 = r2.encrypt(message)
    c3 = r3.encrypt(message)

    decrypted = broadcastAttack([c1, c2, c3], [r1.n, r2.n, r3.n])

    assert decrypted == message

def messageRecovery():

    original = "HELLO"
    oracle = recoveryOracle()
    cipher = oracle.encrypt(original)

    message = oracle.decrypt(cipher) # HELLO
    failed = oracle.decrypt(cipher) # [*] failed decryption with error

    # get all necessary data for attack

    N = oracle.n
    e = oracle.e
    S = 0
    while S < 1:
        S = MT19937(int(time.time())).getNumber() % N

    # start attack intercepting ciphertext

    cipherPrime = (modexp(S, e, N) * cipher) % N
    plainPrime = bytes_to_long(oracle.decrypt(cipherPrime))
    recovered = long_to_bytes(plainPrime * modinv(S, N) % N)

    assert recovered == message == original

if __name__ == "__main__":

    rsaTest()
    broadcastTest()
    messageRecovery()
