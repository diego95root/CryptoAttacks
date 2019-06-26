import random
from DiffieHellman import modexp
from RSA import modinv
from SHA1 import sha1

def sign_DSA(p, q, g, x, message):

    k = random.randint(1, q-1)
    r = modexp(g, k, p) % q
    s = (modinv(k, q) * (int(sha1(message), 16) + x*r)) % q

    if s == 0 or r == 0:
        s, r = sign_DSA(p, q, g)

    return [r, s]

def check_DSA(signature, p, q, g, y, message):

    r, s = signature

    assert 0 < r < q
    assert 0 < s < q

    w = modinv(s, q) % q
    u1 = (int(sha1(message), 16) * w) % q
    u2 = (r * w) % q
    v = ((modexp(g, u1, p) * modexp(y, u2, p)) % p) % q

    return v == r

def bruteforce_k(args, max):

    r, s, hash, q, check = args

    for k in xrange(max):

        x = ((s * k - hash) * modinv(r, q)) % q

        # if the hash wasn't given we could try this:
        # checking if y == modexp(g, x, p)

        if sha1(hex(x)[2:-1]) == "0954edd5e0afe5542a4adf012611a91912a3ec16":

            return (k, x)

    print "[*] No k found, tried {} possible values".format(k)
    return (0, 0)

def bruteforce_repeated_k(args, dataList):

    p, q, g, y = args

    for i in range(0, len(dataList)):
        for j in range(i + 1, len(dataList)):

            try:
                msg1, s1, r1, m1 = dataList[i]
                msg2, s2, r2, m2 = dataList[j]

                num = int(m1, 16) - int(m2, 16)
                tmpDivisor = int(s1) - int(s2)
                div = modinv(tmpDivisor, q)

                k = (num * div) % q

                x = ((int(s1) * k - int(sha1(msg1), 16)) * modinv(int(r1), q)) % q

                assert y == modexp(g, x, p)

                if sha1(hex(x)[2:-1]) == "ca8f6f7c66fa362d40760d135b763eb8527d3d52":

                    return (k, x)

            except:
                pass

    print "[*] No k was repeated (possibly)"
    return (0, 0)

def DSA_test():
    message = "DSA is fun!"
    p = 0x800000000000000089e1855218a0e7dac38136ffafa72eda7859f2171e25e65eac698c1702578b07dc2a1076da241c76c62d374d8389ea5aeffd3226a0530cc565f3bf6b50929139ebeac04f48c3c84afb796d61e5a4f9a8fda812ab59494232c7d2b4deb50aa18ee9e132bfa85ac4374d7f9091abc3d015efc871a584471bb1
    q = 0xf4f47f05794b256174bba6e9b396a7707e563c5b
    g = 0x5958c9d3898b224b12672c0b98e06c60df923cb8bc999d119458fef538b8fa4046c8db53039db620c094c9fa077ef389b5322a559946a71903f990f1f7e0e025e2d7f7cf494aff1a0470f5b64c36b625a097f1651fe775323556fe00b3608c887892878480e99041be601a62166ca6894bdd41a7054ec89f756ba9fc95302291

    x = random.randint(1, q-1)
    y = modexp(g, x, p)

    signature = sign_DSA(p, q, g, x, message)

    assert check_DSA(signature, p, q, g, y, message)

def DSA_from_k():
    m = """For those that envy a MC it can be hazardous to your health\nSo be friendly, a matter of life and death, just like a etch-a-sketch\n"""

    H = int(sha1(m), 16)
    q = 0xf4f47f05794b256174bba6e9b396a7707e563c5b
    y = 0x84ad4719d044495496a3201c8ff484feb45b962e7302e56a392aee4abab3e4bdebf2955b4736012f21a08084056b19bcd7fee56048e004e44984e2f411788efdc837a0d2e5abb7b555039fd243ac01f0fb2ed1dec568280ce678e931868d23eb095fde9d3779191b8c0299d6e07bbb283e6633451e535c45513b2d33c99ea17
    r = 548099063082341131477253921760299949438196259240
    s = 857042759984254168557880549501802188789837994940
    check = 0x0954edd5e0afe5542a4adf012611a91912a3ec16
    range = 2**16

    assert H == 0xd2d0714f014a9784047eaeccf956520045c45265

    k, x = bruteforce_k([r, s, H, q, check], range)

    print "[*] K recovery attack started!"
    print "[*] k recovered    :", k
    print "[*] private key (x):", x

def DSA_from_repeated_k():

    p = 0x800000000000000089e1855218a0e7dac38136ffafa72eda7859f2171e25e65eac698c1702578b07dc2a1076da241c76c62d374d8389ea5aeffd3226a0530cc565f3bf6b50929139ebeac04f48c3c84afb796d61e5a4f9a8fda812ab59494232c7d2b4deb50aa18ee9e132bfa85ac4374d7f9091abc3d015efc871a584471bb1
    q = 0xf4f47f05794b256174bba6e9b396a7707e563c5b
    g = 0x5958c9d3898b224b12672c0b98e06c60df923cb8bc999d119458fef538b8fa4046c8db53039db620c094c9fa077ef389b5322a559946a71903f990f1f7e0e025e2d7f7cf494aff1a0470f5b64c36b625a097f1651fe775323556fe00b3608c887892878480e99041be601a62166ca6894bdd41a7054ec89f756ba9fc95302291
    y = 0x2d026f4bf30195ede3a088da85e398ef869611d0f68f0713d51c9c1a3a26c95105d915e2d8cdf26d056b86b8a7b85519b1c23cc3ecdc6062650462e3063bd179c2a6581519f674a61f1d89a1fff27171ebc1b93d4dc57bceb7ae2430f98a6a4d83d8279ee65d71c1203d2c96d65ebbf7cce9d32971c3de5084cce04a2e147821

    dataList = []

    with open("/Users/diego/desktop/github/CryptoTools/44.txt", "r") as f:

        data = f.read().split("\n")

        for i in range(0, len(data), 4):

            msg = data[i][5:]
            s = data[i+1][3:]
            r = data[i+2][3:]
            m = data[i+3][3:]

            dataList.append([msg, s, r, m])

    f.close()

    k, x = bruteforce_repeated_k([p, q, g, y], dataList)

    print "[*] Multiple key attack started!"
    print "[*] k recovered    :", k
    print "[*] private key (x):", x

if __name__ == "__main__":

    DSA_test()

    DSA_from_k()

    print # formatting purposes

    DSA_from_repeated_k()
