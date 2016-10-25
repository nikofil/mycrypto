import operator
import string
import time
import struct
import random
import Crypto.Cipher.AES
import sha1 as _sha1
import md4 as _md4

from base64 import *
from itertools import *

freq = {'e': 12.70, 't': 9.06, 'a': 8.17, 'o': 7.51, 'i': 6.97, 'n': 6.75, 's': 6.33, 'h': 6.09, 'r': 5.99, 'd': 4.25, 'l': 4.03, 'c': 2.78, 'u': 2.76, 'm': 2.41, 'w': 2.36, 'f': 2.23, 'g': 2.02, 'y': 1.97, 'p': 1.93, 'b': 1.29, 'v': 0.98, 'k': 0.77, 'j': 0.15, 'x': 0.15, 'q': 0.10, 'z': 0.07}

# str to int array
s2a = lambda x: [ord(x) for x in x]
# int array to str
a2s = lambda a: ''.join([chr(x) for x in a])

# decorator to translate strings to int arrays
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
xor = b_inp([0, 1])(lambda x, y: list(imap(operator.xor, x, cycle(y))))
# score of an array based on freq
score = lambda x: reduce(operator.add, map(lambda y: freq[y] if y in freq else 0, x.lower()))
# hamming distance of two arrays
hamm = lambda x, y: sum([bin(x ^ y).count('1') for (x, y) in zip(x, y)])
# most likely key length in range
most_likely_len = lambda c, r: sorted([(l, float(hamm(break_pieces(c, l)[0], break_pieces(c, l)[1]))/l) for l in r], key=operator.itemgetter(1))
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
        iv = r
        res += r
    return res

# decrypt AES CBC
@b_inp([0, 1, 2])
def aes_dec_cbc(key, txt, iv=[0]):
    res = []
    for i in break_pieces(txt, len(key)):
        r = aes_dec_ecb(key, i)
        r = xor(r, iv)
        iv = i
        res += r
    return res

# generate random bytes
randr = lambda x: [random.randrange(256) for _ in xrange(x)]

# throw error with plaintext if unprintable character is found in plaintext
def aes_cbc_throw_err_ascii(x, key):
    txt = aes_dec_cbc(key, x, key)
    txt = txt[:-txt[-1]]
    if not all([chr(cr) in string.printable for cr in txt]):
        return txt
    return None

# retrieve key from above method given a ciphertext when iv = key
def aes_cbc_atk_err_ascii_ivkey(ctxt, key):
    myctxt = ctxt[:16] + [0]*16 + ctxt
    txt = aes_cbc_throw_err_ascii(myctxt, key)
    return xor(txt[:16], txt[32:48])

# ecb or cbc oracle
@b_inp([0])
def ecb_cbc_oracle(txt):
    key = randr(16)
    txt = randr(random.randint(5, 10)) + txt + randr(random.randint(5, 10))
    txt = pad_to(txt, 16)
    if random.choice([True, False]):
        print "Using ECB"
        return aes_enc_ecb(key, txt)
    else:
        print "Using CBC"
        iv = randr(16)
        return aes_enc_cbc(key, txt, iv)

# determine if oracle is ECB or CBC
def is_func_ecb(f):
    txt = 'a' * 64
    r = f(txt)
    return r[16:32] == r[32:48]

# decode one letter from an ECB cipher given an oracle
def decode_ecb_ltr(oracle, known):
    fixed = [0] * (15 - (len(known) % 16))
    blockslen = len(fixed) + len(known) + 1
    target = oracle(fixed)[:blockslen]
    fixed += known
    for i in range(256):
        if oracle(fixed + [i])[:blockslen] == target:
            return i

# decode entire msg given the oracle
def decode_ecb(oracle, tlen):
    known = []
    while len(known) < tlen:
        c = decode_ecb_ltr(oracle, known)
        known.append(c)
    return known

# check padding
@b_inp([0])
def is_padding_valid(txt):
    if len(txt) % 16 != 0:
        return False
    last = txt[-1]
    if not all([x == last for x in txt[-last:]]):
        return False
    return True

# is padding of a cryptomsg valid
def create_pad_oracle(key, iv):
    def pad_oracle(c):
        return is_padding_valid(aes_dec_cbc(key, c, iv))
    return pad_oracle

# decrypt a cbc block using a padding oracle
def decode_cbc_block(prev, blk, pad_oracle):
    known = []
    founddecs = [pad_oracle(prev[:-1] + [i] + blk) for i in range(256)]
    already_valid = pad_oracle(prev + blk)
    if founddecs.count(True) - int(already_valid) > 1:
        raise Exception(str(founddecs.count(True)) + ' possible last bytes')
    if not any(founddecs):
        raise Exception('no valid blocks')
    if already_valid:
        # figure out how many bytes of padding we already have
        # and we instantly figure out that many bytes in the block
        def withv(l, i, val):
            r = l[:]
            r[i] = val
            return r

        for i in range(len(blk), 0, -1):
            if not all([pad_oracle(withv(prev, -i, l) + blk) for l in range(256)]):
                print i, 'byte(s) pad found'
                known = xor([i] * i, prev[-i:])
                break
    while len(known) < len(blk):
        kl = len(known)
        # try to set a valid padding of length kl+1
        # while knowing the rest of the kl bits
        prev2 = prev[:-kl-1] + [0] + [x ^ (kl+1) for x in known]
        for i in range(256):
            prev2[-kl-1] = i
            if pad_oracle(prev2 + blk):
                known = [i ^ (kl+1)] + known
                break
    return xor(known, prev[-len(known):])

# decrypt entire cbc message
def decode_cbc(txt, pad_oracle, iv):
    r = decode_cbc_block(iv, txt[:16], pad_oracle)
    for i in range(1, len(txt)/16):
        ind = i * 16;
        r += decode_cbc_block(txt[:ind], txt[ind:ind+16], pad_oracle)
    return r


# encrypt in ctr mode
@b_inp([0, 1, 2])
def aes_ctr(key, txt, nonce=0):
    r = []
    for i, p in enumerate(break_pieces(txt, 16)):
        blk = struct.pack('<q', nonce) + struct.pack('<q', i)
        c = aes_enc_ecb(key, blk)
        r += xor(p, c)
    return r

# (lazy) edit ctr ciphertext
@b_inp([0, 1, 3, 4, 5])
def aes_ctr_edit(ctxt, offset, newtxt, key, nonce=0):
    ctxt_new = aes_ctr(key, [0] * offset + newtxt, nonce)[offset:offset+len(newtxt)]
    return ctxt[:offset] + ctxt_new + ctxt[offset+len(newtxt):]

# decode ctr ciphertext given aes_ctr_edit
def decode_ctr(ctxt, key, nonce=0):
    xorkey = aes_ctr_edit(ctxt, 0, [0]*len(ctxt), key, nonce)
    return xor(ctxt, xorkey)

# mersenne twister mt19937 prng
_mstate = [0] * 624
_midx = 625

# seeding function
def mt_seed(s):
    global _mstate
    global _midx
    _midx = 624
    _mstate[0] = s
    for i in range(1, 624):
        _mstate[i] = 0xFFFFFFFF & (1812433253 * (_mstate[i-1] ^ (_mstate[i-1] >> 30)) + i)

# prng function
def mt_rand():
    global _mstate
    global _midx
    if _midx > 624:
        raise Exception("must use mt_seed")
    if _midx == 624:
        # twist state
        uppermask = 0xFFFFFFFF << 31
        for i in range(624):
            x = (_mstate[i] & uppermask) + (_mstate[(i+1) % 624] & 0x7FFFFFFF)
            xa = x >> 1
            if x & 1 == 1:
                xa = xa ^ 0x9908B0DF
            _mstate[i] = _mstate[(i+397) % 624] ^ xa
        _midx = 0
    y = _mstate[_midx]
    # diffuse bits
    y ^= (y >> 11) & 0xFFFFFFFF
    y ^= (y << 7) & 0x9D2C5680
    y ^= (y << 15) & 0xEFC60000
    y ^= y >> 18
    _midx += 1
    return y & 0xFFFFFFFF

# reverse the bit diffusion part of mt_rand
def untemper(x):
    # reverse last step
    x ^= x >> 18
    # reverse third step
    x ^= (x << 15) & 0xEFC60000
    # reverse second step
    x ^= (x << 7) & 0x9D2C5680 & 0x3F80
    x ^= (x << 7) & 0x9D2C5680 & 0x1FC000
    x ^= (x << 7) & 0x9D2C5680 & 0xFE00000
    x ^= (x << 7) & 0x9D2C5680 & 0xF0000000
    x &= 0xFFFFFFFF
    # reverse first step
    x ^= (x >> 11) ^ (x >> 22)
    return x

# given 624 outputs of mt_rand without a twist in between,
# splice the state so that the next results match
def clone_rng(rands):
    global _mstate
    global _midx
    _midx = 624
    _mstate = [untemper(x) for x in rands]

#insecure encrypt based on mt19937
@b_inp([0, 1])
def mt_enc(key, txt):
    mt_seed(key & 0xFFFF)
    rlen = mt_rand() & 0xFF
    r = [mt_rand() & 0xFF for _ in xrange(rlen)]
    r += [(mt_rand() & 0xFF) ^ x for x in txt]
    return r

@b_inp([0, 1])
def mt_dec(key, ctxt):
    mt_seed(key & 0xFFFF)
    rlen = mt_rand() & 0xFF
    for i in xrange(rlen):
        mt_rand()
    r = [(mt_rand() & 0xFF) ^ x for x in ctxt[rlen:]]
    return r

# insecure generate token
def gen_token():
    mt_seed(int(time.mktime(time.localtime())))
    i = mt_rand() & 0xFF
    for _ in xrange(i):
        mt_rand()
    return mt_rand()

# SHA1
sha1 = b_inp([0])(lambda x: h2a(_sha1.sha1(a2s(x))))

# SHA1 HMAC
sha1_mac = b_inp([0, 1])(lambda key, msg: sha1(key + msg))

# SHA1 create padding for message of length
sha1_pad_len = lambda l: [1 << 7] + [0]*((64 - ((l + 9) % 64)) % 64) + s2a(struct.pack('>Q', l * 8))

# SHA1 with tampered state
@b_inp([0])
def sha1_tamper(x, prevlen, *args):
    obj = _sha1.Sha1Hash()
    obj._message_byte_length = prevlen
    obj._h = args
    return h2a(obj.update(a2s(x)).hexdigest())

# verify SHA1 signed string
sha1_verify = lambda key, ctxt, ptxt: ctxt == sha1_mac(key, ptxt)

# MD4
@b_inp([0])
def md4(x):
    m = _md4.MD4()
    m.update(a2s(x))
    return h2a(m.digest())

# MD4 HMAC
md4_mac = b_inp([0, 1])(lambda key, msg: md4(key + msg))

# SHA1 create padding for message of length
md4_pad_len = lambda l: [1 << 7] + [0]*((64 - ((l + 9) % 64)) % 64) + s2a(struct.pack('<Q', l * 8))

# verify MD4 signed string
md4_verify = lambda key, ctxt, ptxt: ctxt == md4_mac(key, ptxt)

# MD4 with tampered state
@b_inp([0])
def md4_tamper(x, prevlen, *args):
    obj = _md4.MD4()
    obj.A, obj.B, obj.C, obj.D = args;
    obj._compress(x + md4_pad_len(prevlen + len(x)))
    return h2a(obj.digest())
