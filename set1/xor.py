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

if __name__ == "__main__":

    s1 = "1c0111001f010100061a024b53535009181c"

    s2 = "686974207468652062756c6c277320657965"

    assert xor(s1, s2) == "746865206b696420646f6e277420706c6179"

    # TEST FOR REPEATING KEY XOR

    toEncrypt = "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal".encode("hex")
    key = "ICE".encode("hex")

    assert xor(toEncrypt, key) == "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f"


    # BRUTE-FORCE ONE CHAR XOR FOR A CIPHERTEXT

    currentScore = 0
    result = ""

    for i in range(0, 255):
        s1 = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"


        xorResult = xor(s1, chr(i).encode("hex")).decode("hex").strip()
        score = analyseFrequency(xorResult)

        if score > currentScore:
            result = xorResult
            currentScore = score

    print "[*] Deciphered to: {}\n[*] Score: {}".format(result, str(currentScore))

    # BRUTE-FORCE ONE CHAR XORs FOR MANY CIPHERTEXTS, FIND THE REAL ONE

    """

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

    """
