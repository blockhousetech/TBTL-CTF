KEY = [144, 140, 211, 197, 239, 11, 16, 1, 209, 25, 90, 164, 58, 218, 0, 0]
EXP = [84, 66, 196, 192, 235, 150, 226, 241, 228, 228, 160, 218, 167, 99, 245, 226, 163, 99, 175, 32, 207, 202, 164, 191, 243, 170, 207, 185, 163,  42, 161, 52, 166, 211, 233, 227, 229, 251, 248, 191, 226, 9, 237]

C = [EXP[0], EXP[1]] + [0]*41

k = 0
for i in range(2, 43):
    if EXP[i] == 0:
        continue
    for j in range(i, 43, i):
        if EXP[j]:
            C[j] = EXP[j] ^ KEY[k] 
            EXP[j] = 0
    k += 1

print(bytes(C))
