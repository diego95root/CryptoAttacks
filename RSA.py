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

def PKCS15(data, N, algo):

    ASN1 = {
        'MD5': '\x30\x20\x30\x0c\x06\x08\x2a\x86\x48\x86\xf7\x0d\x02\x05\x05\x00\x04\x10',
        'SHA-1': '\x30\x21\x30\x09\x06\x05\x2b\x0e\x03\x02\x1a\x05\x00\x04\x14',
        'SHA-256': '\x30\x31\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x01\x05\x00\x04\x20',
        'SHA-384': '\x30\x41\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x02\x05\x00\x04\x30',
        'SHA-512': '\x30\x51\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x03\x05\x00\x04\x40',
    }

    try:
        extraFs = 1
        final = "\x00\x01" + "\xff" * extraFs + "\x00" + ASN1[algo] + data.decode("hex")
        return final
    except:
        print "[*] Algorithm not available"

def cubeRoot(x):

    y, y1 = 0, 2

    while y1 != y:
        y = y1
        y1 = (y*(y**3+2*x))//(2*y**3+x)

    return y + 1

class BleichenbacherOracle(RSA):

    def sign(self, data):

        return self.decrypt(bytes_to_long(data))

    def check(self, signature, message):

        all = "\x00" + long_to_bytes(signature ** 3)

        #verify padding, if not return 0
        if all[:3] == "\x00\x01\xff":
            ind = 3
            while all[ind] != "\x00":
                if all[ind] != "\xff":
                    return False
                ind += 1
            """
            # correct implementation checks for leftovers at the end

            ind += 35
            if len(all[ind:]) != 0:
                return False
            """
        else:
            return False

        #return whether hashes are the same
        recovered_hash = all.split("\x00")
        start = len(recovered_hash[1]) + 2 + 15
        recovered_hash = all[start:start+20].encode("hex")

        return sha1(message) == recovered_hash

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

def BleichenbacherAttack():

    e = 3
    p, q = getCoprimes(e)
    oracle = BleichenbacherOracle(p, q, e)

    n = oracle.n
    msg = "hi mom"
    padded = PKCS15(sha1(msg), n, 'SHA-1')

    #extend the message to be 1024 bits / 256 bytes
    print "[*] Starting padding of message:"
    print "[*] Lenght of padded    :", len(padded)
    print "[*] Length of added hex :", len(("\x00"  * ((256 - len(padded)))))
    padded += ("\x00"  * ((256 - len(padded))))
    print "[*] Final length        :", len(padded)

    number = int(padded.encode("hex"), 16)
    signature = cubeRoot(number)

    print "[*] The Bleichenbacher Oracle says the signature is:", oracle.check(signature, msg)

if __name__ == "__main__":

    rsaTest()
    broadcastTest()
    messageRecovery()
    BleichenbacherAttack()
