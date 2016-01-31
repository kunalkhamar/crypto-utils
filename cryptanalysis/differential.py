## Differential cryptanalysis using a chosen-plaintext attack
## For Substitution-Permutation Network (SPN) architecture based ciphers
## The differential characteristic is for Heys Cipher

## Input: ciphertexts corresponding to the chosen plaintexts
## Output: keys with the most matches to the differential characteristic (sorted descending)

ciphertexts = open('ciphertext.txt', 'r')

C = []

def getBits(x, i, j):
    return (x & (2 ** j - 1)) >> i

for line in ciphertexts:
    arr = [int(x, 2) for x in line.split(',')]
    # optimization
    deltaC = arr[2] ^ arr[3]
    if getBits(deltaC, 12, 16) == 0 and getBits(deltaC, 4, 8) == 0:
        C.append((arr[2], arr[3]))
    
invSBox = [ 14,3,4,8,1,12,10,15,7,13,9,6,11,2,0,5 ]
deltaU42_exp = int('0110', 2)
deltaU44_exp = int('0110', 2)
counts = {}

for subkey in range(256):
    counts[subkey] = 0
    keyFrag2 = subkey >> 4
    keyFrag4 = subkey & 15
    
    for i in range(len(C)):
        u42_1 = invSBox[keyFrag2 ^ getBits(C[i][0], 8, 12)]
        u42_2 = invSBox[keyFrag2 ^ getBits(C[i][1], 8, 12)]
        deltaU42 = u42_1 ^ u42_2
        u44_1 = invSBox[keyFrag4 ^ getBits(C[i][0], 0, 4)]
        u44_2 = invSBox[keyFrag4 ^ getBits(C[i][1], 0, 4)]
        deltaU44 = u44_1 ^ u44_2
        
        if deltaU42 == deltaU42_exp and deltaU44 == deltaU44_exp:
            counts[subkey] += 1

for key in sorted(counts, key = counts.get, reverse = True):
    print(key, end='\t')
    print(counts[key])
