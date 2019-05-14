from AES import *
from xor import *
import struct

def encryptAES_CTR(data, key, nonce):

    result = ""
    blockNumber = 0

    for i in range(len(data)/32 + 1):

        block = data[32*i : 32*(i+1)]
        streamData = (struct.pack("<q", nonce) + struct.pack("<q", blockNumber)).encode("hex")

        keystream = encryptAES_ECB(streamData, key).encode("hex")[:len(block)]
        result += xor(block, keystream).decode("hex")
        blockNumber += 1

    return result

def decryptAES_CTR(cipher, key, nonce):

    return encryptAES_CTR(cipher, key, nonce)

if __name__ == "__main__":

    ciphertext = "L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ=="
    cipher = ciphertext.decode("base64").encode("hex")

    print "[*] Decrypted:", decryptAES_CTR(cipher, "YELLOW SUBMARINE", 0)
    assert encryptAES_CTR(decryptAES_CTR(cipher, "YELLOW SUBMARINE", 0).encode("hex"), "YELLOW SUBMARINE", 0).encode("base64").strip() == ciphertext
