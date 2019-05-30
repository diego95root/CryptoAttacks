from AES import *
from MT19937 import *
from xor import *
from SHA1 import *
from MD4 import *
from binascii import unhexlify
from struct import unpack

class serverAES_CBC():

    def __init__(self):
        self.key = generateKey(16)

    def verifyURL(self, url):
        for i in url:
            if ord(i) > 127:
                return "URL is invald, decrypted is: {}".format(url)

    def encrypt(self, data):
        padded = PKCS7(data, 16)
        return encryptAES_CBC(padded.encode("hex"), self.key, self.key.encode("hex")).encode("hex")

    def decrypt(self, data):
        decrypted = decryptAES_CBC(data, self.key, self.key.encode("hex"))
        verified = self.verifyURL(decrypted)
        if verified != None:
            return verified
        else:
            return decrypted

def recoverKeyEqualsIvAES_CBC():

    message = "HELLO MY FRIEND COME VAI ANDIAMO STASERA A MANGIARE INSIEME"

    s1 = "http://example.com/?comment1=cooking%20MCs;userdata="
    s2 = ";comment2=%20like%20a%20pound%20of%20bacon"

    msg = s1 + message.replace(";", "").replace("=", "") + s2

    server = serverAES_CBC()
    encrypted = server.encrypt(msg)

    firstBlock = encrypted[:32]
    encrypted = firstBlock + "0" * 32 + firstBlock + encrypted[96:]

    decrypted = server.decrypt(encrypted)

    result = decrypted.split("is: ")[-1]

    key = xor(result[:16].encode("hex"), result[32:48].encode("hex"))

    assert key == server.key.encode("hex")

    print "[*] Key successfully recovered: {}".format(key)

def sha1MAC(message):
    secret = "This is a real secret!"
    return sha1(secret + message)

def padSHA1(message):

    padding = b'\x80'

    ml = len(message)

    while (len(padding + message) * 8) % 512 != 448:
        padding += b'\x00'

    padding += struct.pack('>Q', ml * 8)

    return message + padding

def padMD4(message):

    padding = b'\x80'

    ml = len(message)

    while (len(padding + message) * 8) % 512 != 448:
        padding += b'\x00'

    padding += struct.pack('<Q', ml * 8)

    return message + padding

class Sha1HashExtensionAttack(Sha1Hash):

    def __init__(self, registers, length):

        self._h = registers
        self._message_byte_length = length
        self._unprocessed = b''

def sha1ExtensionAttack(data, registers, length):
    return Sha1HashExtensionAttack(registers, length).update(data).hexdigest()

class MD4HashExtensionAttack(MD4):

    def __init__(self, registers, length):

        self.h = registers
        self.count = length
        self.remainder = ""

    def finish(self):
        l = len(self.remainder) + 64 * self.count
        self.update( "\x80" + "\x00" * ((55 - l) % 64) + struct.pack("<Q", l * 8))
        out = struct.pack("<4I", *self.h)
        return out.encode("hex")

def MD4ExtensionAttack(data, registers, length):
    return MD4HashExtensionAttack(registers, length).update(data).finish()

def md4(data):
    return MD4().update(data).finish()

def oracleSHA1(data):

    key = "s1qweqqweqweass1qweqqweqweas"
    return sha1(key + data)

def oracleMD4(data):

    key = "ABBBcdcadcaddsdcsdassdkjfnsjgkdfjgndjfkgjndfgnjABBBcdcadcaddsdcsdassdkjfnsjgkdfjgndjfkgjndfgnj"
    return md4(key + data)


if __name__ == "__main__":

    recoverKeyEqualsIvAES_CBC()

    print "[*] Generated SHA1 keyed MAC:", sha1MAC("message")

    assert sha1("a") != sha1ExtensionAttack("a", [0x67452302,0xEFCDAB89,0x98BADCFE,0x10325476,0xC3D2E1F0], 0)

    ############################## SHA1

    print "[*] Starting length extension attack on SHA1"

    originalMsg = "comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon"
    originalSHA = oracleSHA1(originalMsg)

    payload = ";admin=true"
    registers = struct.unpack('>5I', unhexlify(originalSHA))

    for i in range(0, 32):

        processed = padSHA1(i * "a" + originalMsg)
        glue = processed[i + len(originalMsg):]

        forged = sha1ExtensionAttack(payload, registers, len(processed))

        if oracleSHA1(originalMsg + glue + payload) == forged:

            print "-- [*] Length of key is {}".format(i)
            print "-- [*] Hash:", forged

            break

    ############################## MD4

    print "[*] Starting length extension attack on MD4"

    originalMsg = "comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon"
    originalMD4 = oracleMD4(originalMsg)

    payload = ";admin=true"
    registers2 = list(struct.unpack('<4I', unhexlify(originalMD4)))

    for i in range(0, 300):

        processed = padMD4(i * "a" + originalMsg)
        glue = processed[i + len(originalMsg):]

        # the implementation of MD4 counts the blocks processed so division by 64
        # registers2[:] with [:] because the list gets modified, [:] creates new one
        forged = MD4ExtensionAttack(payload, registers2[:], len(processed)/64)

        if oracleMD4(originalMsg + glue + payload) == forged:

            print "-- [*] Length of key is {}".format(i)
            print "-- [*] Hash:", forged

            break

    #
