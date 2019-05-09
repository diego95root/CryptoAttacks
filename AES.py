from Crypto.Cipher import AES
from random import randint

def PKCS7(text, length):

    N = (length - (len(text) % length)) % length

    return text + chr(N) * N

def check_PKCS7(text, length):

    for i in range(0, 16):
        if ord(text[-1]) == i:
            for x in range(i):
                if ord(text[-(x+1)]) != i:
                    raise Exception('Padding not valid on {}'.format(text))

def generateKey(length):

    key = ""

    for i in range(length):
        key += chr(randint(0, 255))

    return key

def detectAES_ECB(data):

    chunks = [data[i:i+16] for i in range(0, len(data), 16)]

    return len(chunks) - len(set(chunks))

def decryptAES_ECB(data, key):

    cipher = AES.new(key, AES.MODE_ECB)

    return cipher.decrypt(data.decode("hex"))

def encryptAES_ECB(data, key):

    cipher = AES.new(key, AES.MODE_ECB)

    return cipher.encrypt(data.decode("hex"))

def encryptAES_CBC(data, key, iv):

    cipher = AES.new(key, AES.MODE_CBC, iv.decode("hex"))

    return cipher.encrypt(data.decode("hex"))

def decryptAES_CBC(data, key, iv):

    cipher = AES.new(key, AES.MODE_CBC, iv.decode("hex"))

    return cipher.decrypt(data.decode("hex"))

def encryptionOracleAES(data):

    key = generateKey(16)

    randomBits1 = generateKey(randint(5,10))
    randomBits2 = generateKey(randint(5,10))

    data = PKCS7(randomBits1 + data.decode("hex") + randomBits2, 16)
    data = data.encode("hex")

    if randint(1, 2) == 1: # MODE_ECB

        return encryptAES_ECB(data, key)

    else: # MODE_CBC

        iv =  generateKey(16).encode("hex")

        return encryptAES_CBC(data, key, iv)

def detectBlockSize(data):

    key = "0" * 16

    blockSize = 0
    last = 0

    for i in range(1, 40):
        tmp = len(encryptAES_ECB(PKCS7("A" * i*2 + data, 16).encode("hex"), key))

        if blockSize == 0:
            blockSize = tmp
            last = tmp

        elif tmp != last:
            blockSize = tmp - last
            last = tmp

    return blockSize

def oneAtATimeECB(data, prefix=""):

    blockStart = (len(data+prefix)/32 + 1) * 32

    secret = ""

    while True:

        payload = prefix + "0"*(blockStart - len(secret) - len(prefix) - 1)

        value = PKCS7(payload + data, 16).encode("hex")
        hex = encryptAES_ECB(value, "0"*16)[blockStart-32:blockStart]

        for i in range(2, 256): # don't include 1 due to padding

            value = PKCS7(payload + secret + chr(i), 16).encode("hex")

            if encryptAES_ECB(value, "0"*16)[blockStart-32:blockStart] == hex:
                secret += chr(i)
                break

        if (i == 255):
            return secret

######################################

def encryptionOracleCBC(data, key, iv):

    s1 = "comment1=cooking%20MCs;userdata="
    s2 = ";comment2=%20like%20a%20pound%20of%20bacon"

    msg = s1 + data.replace(";", "").replace("=", "") + s2
    padded = PKCS7(msg, 16).encode("hex")

    return encryptAES_CBC(padded, key, iv).encode("hex")

def flipBitCBC(encrypted, stringToFind, wantedResult, key, iv):

    differences = []

    block = decryptAES_CBC(encrypted, key, iv).find(stringToFind) / 16

    for i in range(len(stringToFind)):
        if (stringToFind[i] != wantedResult[i]):
            differences.append(i)

    for x in differences:

        offset = (block-1)*32 + x*2
        byte = encrypted[offset:offset+2]

        for i in range(0,0xff):

            tmp = encrypted[:offset] + chr(i).encode("hex") + encrypted[offset+2:]
            decrypted = decryptAES_CBC(tmp, key, iv)

            if decrypted[block*16 + x] == wantedResult[x]:
                encrypted = tmp
                break

    return encrypted

if __name__ == "__main__":

    assert PKCS7("YELLOW SUBMARINE", 20) == "YELLOW SUBMARINE\x04\x04\x04\x04"

    decryptAES_ECB(encryptAES_ECB("datadatadatadata".encode("hex"), PKCS7("HWLLO",16)).encode("hex"), PKCS7("HWLLO",16))

    data = encryptionOracleAES("YELLOW SUBMARINEYELLOW SUBMARINEYELLOW SUBMARINE".encode("hex"))

    if (detectAES_ECB(data) == 0):
        print "[*] Used CBC mode"
    else:
        print "[*] Used ECB mode"


    key = generateKey(16)

    data = "YELLOWYELLOWYELLYELLOWYELLOWYELLYELLOWYELLOWYELL"
    unknown = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK".decode("base64")
    data = PKCS7(data + unknown, 16)

    ct = encryptAES_ECB(data.encode("hex"), key)

    print "[*] Block size is: ", detectBlockSize(unknown)
    if (detectAES_ECB(ct) != 0):
        print "[*] Used EBC mode"
    else:
        print "[*] Used CBC mode"

    print "One-Byte at a time attack:"
    print "======================"
    print oneAtATimeECB(unknown, "AS")
    assert oneAtATimeECB(unknown, "HELLOOSDASDJASLFKADF") == unknown
    assert oneAtATimeECB(unknown) == unknown
    print "======================"

    check_PKCS7("ICE ICE BABY\x04\x04\x04\x04", 20)
    #check_PKCS7("ICE ICE BABY\x05\x05\x05\x05", 20)
    #check_PKCS7("ICE ICE BABY\x01\x02\x03\x04", 20)

    ### BIT FLIPPING ATTACK AES MODE_CBC

    key = generateKey(16)
    iv = generateKey(16).encode("hex")

    encrypted = encryptionOracleCBC("XadminXtrueX", key, iv)
    encryptedModified = flipBitCBC(encrypted, "XadminXtrueX", ";admin=true;", key, iv)

    print encrypted
    print encryptedModified
    print decryptAES_CBC(encrypted, key, iv).strip()
    print decryptAES_CBC(encryptedModified, key, iv).strip()

    """

    with open("/Users/diego/desktop/github/CryptoTools/set1/10.txt", "r") as file:

        text = file.read().strip().decode("base64").encode("hex")

        iv = PKCS7('', 16).encode("hex")
        key = 'YELLOW SUBMARINE'

        print decryptAES_CBC(text, key, iv)


    with open("/Users/diego/desktop/github/CryptoTools/set1/7.txt", "r") as file:

        text = file.read().strip().decode("base64").encode("hex")

        key = 'YELLOW SUBMARINE'

        decryptAES_ECB(text, key)



    with open("/Users/diego/desktop/github/CryptoTools/set1/8.txt", "r") as file:

        ciphers = file.read().split("\n")[:-1]

        # beautify this way of getting results
        result = ""
        score = 0

        for i in ciphers:
            tmpScore = detectAES_ECB(i.decode("hex"))
            if tmpScore > score:
                result = i
                score = tmpScore

        print score
        print result

    """
