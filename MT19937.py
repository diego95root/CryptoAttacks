import time
from random import randint


class MT19937(object):

    def __init__(self, seed = 5489):
        self.state = [0]*624
        self.f = 1812433253
        self.m = 397
        self.u = 11
        self.s = 7
        self.b = 0x9D2C5680
        self.t = 15
        self.c = 0xEFC60000
        self.l = 18
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
        y = y^(y>>self.u)
        y = y^((y<<self.s)&self.b)
        y = y^((y<<self.t)&self.c)
        y = y^(y>>self.l)
        self.index+=1
        return int(0xFFFFFFFF & y)

def MTSeedCracker(final, firstNumber):

    print "[*] Cracking seed for number: {}".format(firstNumber)

    while True:
        final -= 1
        test = MT19937(final)
        number = test.getNumber()
        if number == firstNumber:
            print "[*] Seed for first number ({}) found: {}".format(number, final)
            break

if __name__ == "__main__":

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
