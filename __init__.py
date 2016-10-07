import operator
import string
import Crypto.Cipher.AES

from base64 import *
from itertools import *

freq = {'e': 12.70, 't': 9.06, 'a': 8.17, 'o': 7.51, 'i': 6.97, 'n': 6.75, 's': 6.33, 'h': 6.09, 'r': 5.99, 'd': 4.25, 'l': 4.03, 'c': 2.78, 'u': 2.76, 'm': 2.41, 'w': 2.36, 'f': 2.23, 'g': 2.02, 'y': 1.97, 'p': 1.93, 'b': 1.29, 'v': 0.98, 'k': 0.77, 'j': 0.15, 'x': 0.15, 'q': 0.10, 'z': 0.07}

# str to int array
s2a = lambda x: [ord(x) for x in x]
# int array to str
a2s = lambda a: ''.join([chr(x) for x in a])

def b_inp(r):
    def wrapper(f):
        def wrapped(*args):
            args2 = [s2a(x) if (i in r and type(x) == str) else x for (i, x) in enumerate(args)]
            return f(*args2)
        return wrapped
    return wrapper

# break string into pieces of same length
break_pieces = lambda s, l: [s[i:i+l] for i in range(len(s))[::l]]
# hex str to int array
h2a = lambda x: [int(a, 16) for a in break_pieces(x, 2)]
# int array to hex str
a2h = lambda x: ''.join([hex(a)[2:].zfill(2) for a in x])
# base64 encode to str
b64 = lambda x: b64encode(''.join(map(chr, x)))
# base64 decode to array
u64 = lambda x: map(ord, b64decode(x))
# xor msg array with key array
xor = lambda x, y: list(imap(operator.xor, x, cycle(y)))
# score of an array based on freq
score = lambda x: reduce(operator.add, map(lambda y: freq[y] if y in freq else 0, x.lower()))
# hamming distance of two arrays
hamm = lambda x, y: sum([bin(x ^ y).count('1') for (x, y) in zip(x, y)])
# most likely key length in range
most_likely_lens = lambda c, r: sorted([(l, float(hamm(break_pieces(c, l)[0], break_pieces(c, l)[1]))/l) for l in r], key=operator.itemgetter(1))
# crack repeating xor cipher
def crackxor(txt, to_len=30, print_txt=True):
    key_lens = most_likely_len(txt, range(2, to_len))
    ret = []
    for key_len in key_lens:
        key_len = key_len[0]
        groups = izip_longest(*break_pieces(txt, key_len), fillvalue=None)
        def rate_key(txt, key):
            dec = [x ^ key for x in txt if x is not None]
            for d in dec:
                if d not in s2a(string.printable):
                    return 0
            return score(a2s(dec))
        res = [max([(k, rate_key(g, k)) for k in range(256)], key=operator.itemgetter(1)) for g in groups]
        if all([r[1] > 0 for r in res]):
            key = [r[0] for r in res]
            ret.append(key)
            if print_txt:
                print(a2s(xor(txt, key)))
    return ret
# encrypt AES ECB
aes_enc_ecb = b_inp([0, 1])(lambda key, txt: s2a(Crypto.Cipher.AES.new(a2s(key), Crypto.Cipher.AES.MODE_ECB).encrypt(a2s(txt))))
# decrypt AES ECB
aes_dec_ecb = b_inp([0, 1])(lambda key, txt: s2a(Crypto.Cipher.AES.new(a2s(key), Crypto.Cipher.AES.MODE_ECB).decrypt(a2s(txt))))
# PKCS7 padding
pad_to = b_inp([0])(lambda x, l: x + [l - (len(x) % l)] * (l - (len(x) % l)))
# encrypt AES CBC
@b_inp([0, 1, 2])
def aes_enc_cbc(key, txt, iv=[0]):
    res = []
    for i in break_pieces(txt, len(key)):
        i = xor(i, iv)
        r = aes_enc_ecb(key, i)
        iv = i
        res += r
    return res
# decrypt AES CBC
@b_inp([0, 1, 2])
def aes_dec_cbc(key, txt, iv=[0]):
    res = []
    for i in break_pieces(txt, len(key)):
        r = aes_dec_ecb(key, i)
        iv = i
        i = xor(i, iv)
        res += r
    return res[:-res[-1]]
