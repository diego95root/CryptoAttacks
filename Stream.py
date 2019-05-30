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

def breakFixedNonce(ciphers):

    stream = ""
    result = []

    for i in range( max([len(i) for i in ciphers]) ):

        s = ""
        bestResult = 0
        byte = 0

        for x in ciphers:
            try: s += x[i]
            except: pass

        s = s.encode("hex")

        for j in range(256):
            res = analyseFrequency(xor(s, chr(j).encode("hex")).decode("hex"))
            if res > bestResult:
                bestResult = res
                byte = chr(j).encode("hex")

        stream += byte

    for i in range(len(ciphers)):
        result.append( xor(ciphers[i].encode("hex"), stream).decode("hex")[:len(ciphers[i])] )
    return result

def editCT(ciphertext, key, offset, newtext):
    decrypted = decryptAES_CTR(ciphertext, key, 0)
    modified = (decrypted[:offset] + newtext + decrypted[offset + len(newtext):]).encode("hex")
    encrypted = encryptAES_CTR(modified, key, 0)
    return encrypted

def breakRandomAccessCTR(cipher, key):

    plainPrime = "a"*(len(cipher)/2)
    edited = editCT(cipher, key, 0, plainPrime).encode("hex")

    # Plaintext = plaintext' ^ ciphertext ^ ciphertext'
    # this is because both ciphertext and ciphertext'
    # have been xor'ed with the stream and so it cancels
    return xor(xor(cipher, edited), plainPrime.encode("hex"))

def encryptionOracleCTR(data, key):

    s1 = "comment1=cooking%20MCs;userdata="
    s2 = ";comment2=%20like%20a%20pound%20of%20bacon"

    msg = s1 + data.replace(";", "").replace("=", "") + s2
    padded = PKCS7(msg, 16).encode("hex")

    return encryptAES_CTR(padded, key, 0).encode("hex")

def flipBitCTR(encrypted, stringToFind, wantedResult, key):

    differences = []

    block = decryptAES_CTR(encrypted, key, 0).find(stringToFind) / 16

    for i in range(len(stringToFind)):
        if (stringToFind[i] != wantedResult[i]):
            differences.append(i)

    for x in differences:

        offset = block*32 + x*2
        byte = encrypted[offset:offset+2]

        for i in range(0,0xff):

            tmp = encrypted[:offset] + chr(i).encode("hex") + encrypted[offset+2:]
            decrypted = decryptAES_CTR(tmp, key, 0)

            if decrypted[block*16 + x] == wantedResult[x]:
                encrypted = tmp
                break

    return encrypted


if __name__ == "__main__":

    key = generateKey(16)
    encrypted = encryptionOracleCTR("XadminXtrueX", key)
    print decryptAES_CTR(encrypted, key, 0).strip()
    encryptedModified = flipBitCTR(encrypted, "XadminXtrueX", ";admin=true;", key)
    print decryptAES_CTR(encryptedModified, key, 0).strip()

    """
    with open("/Users/diego/desktop/github/CryptoTools/7.txt", "r") as file:

        text = file.read().strip().decode("base64").encode("hex")

        key = 'YELLOW SUBMARINE'

        plain = decryptAES_ECB(text, key)

    plain = plain.encode("hex")
    key = generateKey(16)
    cipher = encryptAES_CTR(plain, key, 0).encode("hex")

    assert breakRandomAccessCTR(cipher, key) == plain

    """

    """
    ciphertext = "L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ=="
    cipher = ciphertext.decode("base64").encode("hex")

    print "[*] Decrypted:", decryptAES_CTR(cipher, "YELLOW SUBMARINE", 0)
    assert encryptAES_CTR(decryptAES_CTR(cipher, "YELLOW SUBMARINE", 0).encode("hex"), "YELLOW SUBMARINE", 0).encode("base64").strip() == ciphertext

    plains64 = ["SSBoYXZlIG1ldCB0aGVtIGF0IGNsb3NlIG9mIGRheQ==", "Q29taW5nIHdpdGggdml2aWQgZmFjZXM=", "RnJvbSBjb3VudGVyIG9yIGRlc2sgYW1vbmcgZ3JleQ==", "RWlnaHRlZW50aC1jZW50dXJ5IGhvdXNlcy4=", "SSBoYXZlIHBhc3NlZCB3aXRoIGEgbm9kIG9mIHRoZSBoZWFk", "T3IgcG9saXRlIG1lYW5pbmdsZXNzIHdvcmRzLA==", "T3IgaGF2ZSBsaW5nZXJlZCBhd2hpbGUgYW5kIHNhaWQ=", "UG9saXRlIG1lYW5pbmdsZXNzIHdvcmRzLA==", "QW5kIHRob3VnaHQgYmVmb3JlIEkgaGFkIGRvbmU=", "T2YgYSBtb2NraW5nIHRhbGUgb3IgYSBnaWJl", "VG8gcGxlYXNlIGEgY29tcGFuaW9u", "QXJvdW5kIHRoZSBmaXJlIGF0IHRoZSBjbHViLA==", "QmVpbmcgY2VydGFpbiB0aGF0IHRoZXkgYW5kIEk=", "QnV0IGxpdmVkIHdoZXJlIG1vdGxleSBpcyB3b3JuOg==", "QWxsIGNoYW5nZWQsIGNoYW5nZWQgdXR0ZXJseTo=", "QSB0ZXJyaWJsZSBiZWF1dHkgaXMgYm9ybi4=", "VGhhdCB3b21hbidzIGRheXMgd2VyZSBzcGVudA==", "SW4gaWdub3JhbnQgZ29vZCB3aWxsLA==", "SGVyIG5pZ2h0cyBpbiBhcmd1bWVudA==", "VW50aWwgaGVyIHZvaWNlIGdyZXcgc2hyaWxsLg==", "V2hhdCB2b2ljZSBtb3JlIHN3ZWV0IHRoYW4gaGVycw==", "V2hlbiB5b3VuZyBhbmQgYmVhdXRpZnVsLA==", "U2hlIHJvZGUgdG8gaGFycmllcnM/", "VGhpcyBtYW4gaGFkIGtlcHQgYSBzY2hvb2w=", "QW5kIHJvZGUgb3VyIHdpbmdlZCBob3JzZS4=", "VGhpcyBvdGhlciBoaXMgaGVscGVyIGFuZCBmcmllbmQ=", "V2FzIGNvbWluZyBpbnRvIGhpcyBmb3JjZTs=", "SGUgbWlnaHQgaGF2ZSB3b24gZmFtZSBpbiB0aGUgZW5kLA==", "U28gc2Vuc2l0aXZlIGhpcyBuYXR1cmUgc2VlbWVkLA==", "U28gZGFyaW5nIGFuZCBzd2VldCBoaXMgdGhvdWdodC4=", "VGhpcyBvdGhlciBtYW4gSSBoYWQgZHJlYW1lZA==", "QSBkcnVua2VuLCB2YWluLWdsb3Jpb3VzIGxvdXQu", "SGUgaGFkIGRvbmUgbW9zdCBiaXR0ZXIgd3Jvbmc=", "VG8gc29tZSB3aG8gYXJlIG5lYXIgbXkgaGVhcnQs", "WWV0IEkgbnVtYmVyIGhpbSBpbiB0aGUgc29uZzs=", "SGUsIHRvbywgaGFzIHJlc2lnbmVkIGhpcyBwYXJ0", "SW4gdGhlIGNhc3VhbCBjb21lZHk7", "SGUsIHRvbywgaGFzIGJlZW4gY2hhbmdlZCBpbiBoaXMgdHVybiw=", "VHJhbnNmb3JtZWQgdXR0ZXJseTo=", "QSB0ZXJyaWJsZSBiZWF1dHkgaXMgYm9ybi4="]

    ciphers = []

    key = generateKey(16)
    for i in plains64:
        hex = i.decode("base64").encode("hex")
        ciphers.append(encryptAES_CTR(hex, key, 0))

    print breakFixedNonce(ciphers)

    ciphers2 = []

    with open("/Users/diego/desktop/github/CryptoTools/20.txt", "r") as file:
        for i in file.readlines():
            hex = i.strip().decode("base64").encode("hex")
            ciphers2.append(encryptAES_CTR(hex, key, 0))

    print breakFixedNonce(ciphers2)

    # MAKE THEM MORE ACCURATE
    """
