def xor(v1, v2):

    v1 = v1.decode("hex")
    v2 = v2.decode("hex")

    returnValue = ""

    if (len(v1) > len(v2)):
        maxLength = len(v1)
    else:
        maxLength = len(v2)

    for i in range(maxLength):
        returnValue += chr(ord(v1[i%len(v1)]) ^ ord(v2[i%len(v2)]))

    return returnValue.encode("hex")

def analyseFrequency(text):

    text = text.lower()

    character_frequencies = {
        'a': .08167, 'b': .01492, 'c': .02782, 'd': .04253,
        'e': .12702, 'f': .02228, 'g': .02015, 'h': .06094,
        'i': .06094, 'j': .00153, 'k': .00772, 'l': .04025,
        'm': .02406, 'n': .06749, 'o': .07507, 'p': .01929,
        'q': .00095, 'r': .05987, 's': .06327, 't': .09056,
        'u': .02758, 'v': .00978, 'w': .02360, 'x': .00150,
        'y': .01974, 'z': .00074, ' ': .13000
    }

    res = {}

    for each in text:
        res[each] = res.get(each, 0) + 1

    return sum([res[i] * character_frequencies.get(i, 0) for i in res])

def bruteforceSingleXor(text):

    currentScore = 0
    result = ""
    char = ""

    for i in range(0, 255):

        xorResult = xor(text, chr(i).encode("hex")).decode("hex").strip()
        score = analyseFrequency(xorResult)

        if score > currentScore:
            result = xorResult
            currentScore = score
            char = chr(i).encode("hex")

    return [result, char]

def hammingDistance(s1, s2):

    if len(s1) != len(s2):
        print "[*] Lengths for hamming distance need to be the same"
        return 0

    distance = 0

    for i in range(len(s1)):

        xorForBits = ord(s1[i]) ^ ord(s2[i])

        while xorForBits:
            distance += (xorForBits & 1)
            xorForBits >>= 1

    return distance

def bruteforceXorKey(text):

    distances = {}

    raw = text.decode("hex")

    for i in range(2, 40):
        s1 = raw[:i]
        s2 = raw[i:2*i]
        s3 = raw[2*i:3*i]
        s4 = raw[3*i:4*i]

        normalized = float(hammingDistance(s1, s2) + hammingDistance(s2, s3) + hammingDistance(s3, s4))/(i*3)

        distances[i] = normalized

    length = sorted(distances, key=distances.get)

    result = ""
    score = 0

    for x in range(5):

        key = ""

        for i in range(length[x]): # number of sub-blocks determined by key length
            subBlock = ""
            for j in range(len(raw)): # for all bytes
                if j % length[x] == i: # check if it is the nth byte
                    subBlock += raw[j]
            key += bruteforceSingleXor(subBlock.encode("hex"))[1].decode("hex")

        tmpText = xor(text, key.encode("hex")).decode("hex")
        tmpScore = analyseFrequency(tmpText)

        if tmpScore > score:
            score = tmpScore
            result = tmpText

    print result

def tests_xor():
    s1 = "1c0111001f010100061a024b53535009181c"

    s2 = "686974207468652062756c6c277320657965"

    assert xor(s1, s2) == "746865206b696420646f6e277420706c6179"

    # TEST FOR REPEATING KEY XOR

    toEncrypt = "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal".encode("hex")
    key = "ICE".encode("hex")

    assert xor(toEncrypt, key) == "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f"

def tests_oneXor():

    # BRUTE-FORCE ONE CHAR XOR FOR A CIPHERTEXT

    result = bruteforceSingleXor("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736")

    print "[*] Deciphered to: {}".format(result)

    # BRUTE-FORCE ONE CHAR XORs FOR MANY CIPHERTEXTS, FIND THE REAL ONE

    currentScore2 = 0
    result2 = ""

    with open("/Users/diego/desktop/github/CryptoTools/set1/possible.txt", "r") as file:
        for i in file.readlines():
            for x in range(0, 255):
                xorResult = xor(i.strip(), chr(x).encode("hex")).decode("hex").strip()
                score = analyseFrequency(xorResult)

                if score > currentScore2:
                    result2 = xorResult
                    currentScore2 = score

    print "[*] Deciphered to: {}\n[*] Score: {}".format(result2, str(currentScore2))

if __name__ == "__main__":

    with open("/Users/diego/desktop/github/CryptoTools/set1/possibleXorKeyBrute.txt", "r") as file:

        text = file.read().strip().decode("base64").encode("hex")

        bruteforceXorKey(text)
