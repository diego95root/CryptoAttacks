import time
from random import randint
from AES import *

class MT19937():

    def __init__(self, seed = 5489):
        self.state = [0]*624
        self.f = 1812433253
        self.m = 397
        self.index = 624
        self.lower_mask = (1 << 31) - 1
        self.upper_mask = 1 << 31

        self.state[0] = seed
        for i in range(1,624):
            self.state[i] = int(0xFFFFFFFF & (self.f * (self.state[i-1] ^ (self.state[i-1] >> 30)) + i))

    def twist(self):
        for i in range(624):
            temp = int(0xFFFFFFFF & (self.state[i] & self.upper_mask) + (self.state[(i+1) % 624] & self.lower_mask))
            temp_shift = temp >> 1
            if temp % 2 != 0:
                temp_shift = temp_shift ^ 0x9908b0df
            self.state[i] = self.state[(i + self.m) % 624] ^ temp_shift
        self.index = 0

    def getNumber(self):
        if self.index >= 624:
            self.twist()
        y = self.state[self.index]
        y = y ^ ((y >> 11) & 0xFFFFFFFF)
        y = y ^ ((y <<  7) & 0x9D2C5680)
        y = y ^ ((y << 15) & 0xEFC60000)
        y = y ^ (y >> 18)
        self.index += 1
        return int(0xFFFFFFFF & y)

class MT19937Clone(MT19937):

    def __init__(self, state):
        self.state = state
        self.f = 1812433253
        self.m = 397
        self.index = 624
        self.lower_mask = (1 << 31) - 1
        self.upper_mask = 1 << 31

def MTSeedCracker(final, firstNumber):

    print "[*] Cracking seed for number: {}".format(firstNumber)

    while True:
        final -= 1
        test = MT19937(final)
        number = test.getNumber()
        if number == firstNumber:
            print "[*] Seed for first number ({}) found: {}".format(number, final)
            break

def untemperValue(value):

    y1 = value ^ (value >> 18) # first op

    y2 = (y1 ^ ((y1 << 15) & 0xEFC60000)) # second op

    tmp = ((y2 << 7) & 0x9D2C5680) ^ y2 # third op
    tmp = ((tmp << 7) & 0x9D2C5680) ^ y2
    tmp = ((tmp << 7) & 0x9D2C5680) ^ y2
    y3 = ((tmp << 7) & 0x9D2C5680) ^ y2

    y4 = ((y3 ^ (y3 >> 11)) >> 11) ^ y3 # fourth op

    return y4

class MT19937StreamCipher(MT19937):

    def __init__(self, seed = 5489):

        self.seed = seed
        self.state = [0]*624
        self.f = 1812433253
        self.m = 397
        self.index = 624
        self.lower_mask = (1 << 31) - 1
        self.upper_mask = 1 << 31

        self.state[0] = seed & 0xffff # only get 16-bit seed
        for i in range(1,624):
            self.state[i] = int(0xFFFFFFFF & (self.f * (self.state[i-1] ^ (self.state[i-1] >> 30)) + i))

    def encrypt(self, value):

        v = value.decode("hex")
        n = self.getNumber()

        cipher = ""

        for i in range(len(v)):
            cipher += chr(ord(v[i]) ^ (n & 0xff))
            n = n >> 8
            if n == 0:
                n = self.getNumber()

        self.__init__(self.seed) # restore MT to initial state

        return cipher.encode("hex")

    def decrypt(self, value):
        return self.encrypt(value)

def breakMT19937StreamCipher(cipher):

    plain = ""
    score = 0
    seed = 0

    for i in range(0xffff):
        plainTmp = MT19937StreamCipher(i).decrypt(cipher).decode("hex")
        res = analyseFrequency(plainTmp)
        if res > score:
            score = res
            plain = plainTmp
            seed = i

    return [plain, score, seed]

if __name__ == "__main__":

    gen = MT19937(12731)

    state = []

    # tap to get all the state

    for i in range(624):
        a = gen.getNumber()
        state.append(untemperValue(a))

    copy = MT19937Clone(state) # create new generator with the recovered state

    assert copy.getNumber() == gen.getNumber()

    ######### challenge 24

    key = 65534
    assert key < 65535
    plain = "aasdsnfjksngkretAAAAAAAAAAAAAAAA".encode("hex")

    gen = MT19937StreamCipher(key)
    cipher = gen.encrypt(plain)
    print gen.decrypt(cipher).decode("hex")

    print breakMT19937StreamCipher(cipher)

    """
    initial = int(time.time())

    s1 = randint(40, 1000)/20
    print "We are going to wait for {} seconds".format(s1)
    time.sleep(s1)

    timestamp = int(time.time())
    gen = MT19937(timestamp)

    s2 = randint(40, 1000)/20
    print "We are going to wait for {} seconds".format(s2)
    time.sleep(s2)

    out = gen.getNumber()
    final = int(time.time())

    MTSeedCracker(final, out)

    print "Original seed was {}".format(timestamp)
    """
