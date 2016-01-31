## Linear cryptanalysis using a known-plaintext attack
## For Substitution-Permutation Network (SPN) architecture based ciphers
## The linear approximation is for Heys Cipher

## Input: plaintext-ciphertext pairs encoded using the same key
## Output: keys which result in the largest bias (sorted descending)

plaintexts = open('plaintexts.txt', 'r')
ciphertexts = open('ciphertext.txt', 'r')

P = []
C = []

for line in plaintexts:
    P.append(line)
for line in ciphertexts:
    C.append(line)

invSBox = [ 14,3,4,8,1,12,10,15,7,13,9,6,11,2,0,5 ]

def getBit(x, i):
    return (x >> i) & 1

biases = {}
keyFrag2 = int('1110', 2)
keyFrag4 = int('1101', 2)

for key in range(256):
    counts = [ 0,0 ]
    keyFrag1 = key >> 4;
    keyFrag3 = key & 15;
    
    for i in range(len(C)):
        cBits1 = int(C[i][0:4], 2)
        cBits2 = int(C[i][4:8], 2)
        cBits3 = int(C[i][8:12], 2)
        cBits4 = int(C[i][12:16], 2)
        v1 = keyFrag1 ^ cBits1
        v2 = keyFrag2 ^ cBits2
        v3 = keyFrag3 ^ cBits3
        v4 = keyFrag4 ^ cBits4
        u1 = invSBox[v1]
        u2 = invSBox[v2]
        u3 = invSBox[v3]
        u4 = invSBox[v4]
        xor = getBit(u1, 2) ^ getBit(u2, 2) ^ getBit(u3, 2) ^ getBit(u4, 2) \
                  ^ int(P[i][0]) ^ int(P[i][3]) ^ int(P[i][8]) ^ int(P[i][11])
        counts[xor] += 1

    total = counts[0] + counts[1]
    bias = counts[1]/total - 1/2
    biases[key] = abs(bias)

for key in sorted(biases, key=biases.__getitem__, reverse=True):
    print(str(key) + '\t' + str(biases[key]))
