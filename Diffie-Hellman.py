from SHA1 import *

def diffieHellman(a, b):

    p = 37
    g = 5

    A = (g ** a) % p
    B = (g ** b) % p

    s1 = (A**b) % p
    s2 = (B**a) % p

    assert  s1 == s2

    return sha1(str(s1))

if __name__ == "__main__":

    print diffieHellman(1, 2)
