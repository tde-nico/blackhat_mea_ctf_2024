from pwn import xor

flag = bytearray([ord('0')] * 100)

flag[14] = ord('a')
flag[18] = ord('a')
flag[24] = ord('a')
flag[32] = ord('a')
flag[36] = ord('a')
flag[62] = ord('a')

# 9 == flag[7:9] - flag[9:11] and 680 == flag[89:92] + flag[92:94]

flag[1] = ord('0') # x <- 9 * (9 - 5 + 4 + 6 - 3 - 2 - 3 - 6)

flag[25] = ord('2')
flag[26] = ord('5')
flag[27] = ord('2')
flag[28] = ord('1')
flag[29] = ord('3')

flag[7] = ord('2')
flag[8] = ord('9')
flag[9] = ord('2')
flag[10] = ord('0')
flag[11] = ord('2')

flag[16] = ord('f')
flag[30] = ord('f')

flag[42] = ord('d')
flag[50] = ord('d')
flag[56] = ord('d')
flag[80] = ord('d')

flag[54] = ord('e')
flag[84] = ord('e')
flag[12] = ord('e')

flag[6] = ord('b')

flag[76] = ord("8")
flag[93] = ord("3")
flag[13] = ord("0")
flag[26] = ord("5")
flag[87] = ord("3")
flag[88] = ord("c")
flag[81] = ord("0")
flag[86] = ord("0")
flag[17] = ord("1")
flag[18] = ord("a")
flag[39] = ord("2")
flag[58] = ord("2")
flag[19] = ord("2")
flag[20] = ord("b")
flag[31] = ord("3")
flag[44] = ord("1")
flag[49] = ord("3")
flag[55] = ord("3")
flag[44] = ord("1")
flag[45] = ord("2")
flag[66] = ord("c")


flag[67] = ord("2")
flag[68] = ord("2")
flag[69] = ord("1")
flag[70] = ord("0")
flag[71] = ord("3")
#(67, 71, 22103)
flag[72] = ord("5")
flag[73] = ord("0")
flag[74] = ord("1")
flag[75] = ord("3")
flag[76] = ord("8")
#(72, 76, 50138)
flag[37] = ord("1")
flag[38] = ord("9")
flag[39] = ord("2")
flag[40] = ord("3")
flag[41] = ord("0")
#(37, 41, 19230)
flag[43] = ord("1")
flag[44] = ord("1")
flag[45] = ord("2")
flag[46] = ord("0")
flag[47] = ord("2")
#(43, 47, 11202)

flag[77] = ord("7")
flag[78] = ord("6")
flag[79] = ord("3")
#(77, 79, 763)
flag[85] = ord("3")
flag[86] = ord("0")
flag[87] = ord("3")
#(85, 87, 303)
flag[59] = ord("7")
flag[60] = ord("5")
flag[61] = ord("3")
#(59, 61, 753)
flag[39] = ord("2")
flag[40] = ord("3")
flag[41] = ord("0")
#(39, 41, 230)
flag[21] = ord("3")
flag[22] = ord("6")
flag[23] = ord("1")
#(21, 23, 361)
flag[51] = ord("7")
flag[52] = ord("1")
flag[53] = ord("3")
#(51, 53, 713)
flag[33] = ord("3")
flag[34] = ord("5")
flag[35] = ord("1")
#(33, 35, 351)
flag[45] = ord("2")
flag[46] = ord("0")
flag[47] = ord("2")
#(45, 47, 202)
flag[63] = ord("7")
flag[64] = ord("0")
flag[65] = ord("7")
#(63, 65, 707)

# 1 = flag[51] - flag[22]
# -2 = flag[17] - flag[87]
#9 = flag[7] - flag[9]
#9 = flag[8] - flag[10]

flag[92] = flag[26] = flag[34] = flag[60] = flag[72]
flag[48] = flag[78] = flag[89] = flag[22]
flag[59] = flag[63] = flag[65] = flag[77] = flag[91] = flag[51]
flag[23] = flag[28] = flag[35] = flag[37] = flag[43] = flag[44] = flag[52] = flag[69] = flag[74] = flag[17]

# (94, 82, 6)
# (1, 86, 10)
# (90, 83, 9)
# (9, 11, 15)
# (29, 61, 57)
flag[94] = flag[82] = flag[6]
flag[1] = flag[86] = flag[10]
flag[90] = flag[83] = flag[9]
flag[11] = flag[15] = flag[9]
flag[29] = flag[57] = flag[61]

enc_flag = flag[1:95]
print(enc_flag)

bin_enc_flag = bytes.fromhex(enc_flag.decode()) # '00000b29202e0a2f1a2b361a25213f3a351a19230d1120263d713e3d32753a707c2210350138763d0b2e303c62753b'
key = b'BHMEAISTHEBESTCTFEVERBETTERTHANALLOFTHEOTHERCTF'
f = xor(bin_enc_flag, key)
print(f)

# BHFlagY{Rnt_vu|ns_Of_Seri4liz4t10n_sUp3r_fun!!}
