import operator
import string
import time
import struct
import random
import hashlib
import requests
import Crypto.Cipher.AES
import pyprimes
import salsa20
import zlib
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
# int to int array
i2a = lambda x: [int(a, 16) for a in break_pieces(('%x' % x).zfill((len('%x' % x) + 1) & ~1), 2)]
# xor msg array with key array
xor = b_inp([0, 1])(lambda x, y: list(imap(operator.xor, x, cycle(y))))
# score of an array based on freq
score = lambda x: reduce(operator.add, map(lambda y: freq[y] if y in freq else 0, x.lower()))
# hamming distance of two arrays
hamm = lambda x, y: sum([bin(x ^ y).count('1') for (x, y) in zip(x, y)])
# string to int
s2i = b_inp([0])(lambda x: reduce(lambda y, z: y*256+z, x))
# int to string
@b_inp([0])
def i2s(x):
    r = ''
    while x > 0:
        r = chr(x%256) + r
        x /= 256
    return r
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
# PKCS1v1.5 padding
pkcs15 = b_inp([0])(lambda x, l: [0, 2] + [r if r != 0 else 1 for r in randr(l - len(x) - 3)] + [0] + x)

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

# SHA1 to int
sha1i = lambda msg: int(a2h(sha1(msg)), 16)

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

# HMAC SHA1
@b_inp([0, 1])
def hmac_sha1(key, msg):
    if (len(key) > 64):
        key = sha1(key)
    if (len(key) < 64):
        key = key + [0]*(64 - len(key))
    opad = xor([0x5c]*64, key)
    ipad = xor([0x36]*64, key)
    return sha1(opad + sha1(ipad + msg))

# HMAC SHA256
@b_inp([0, 1])
def hmac_sha256(key, msg):
    sha256 = lambda x: h2a(hashlib.sha256(str(x)).hexdigest())
    if (len(key) > 64):
        key = sha256(key)
    if (len(key) < 64):
        key = key + [0]*(64 - len(key))
    opad = xor([0x5c]*64, key)
    ipad = xor([0x36]*64, key)
    return sha256(opad + sha256(ipad + msg))

# break HMAC SHA1 with timing side channel attack
def break_hmac_sha1(f):
    getst = lambda x: requests.get(x).status_code
    url = 'http://localhost:8081/hmac?file='+f+'&signature='
    while True:
        cur = [0] * 256
        print url
        if url[-1] != '=':
            if getst(url) == 200:
                return url
        for j in range(256):
            url2 = url + '{:02x}'.format(j)
            t1 = time.time()
            for i in range(50):
                getst(url2)
            elapsed = time.time() - t1
            cur[j] += elapsed
        b = cur.index(max(cur))
        url += '{:02x}'.format(b)

# Diffie-Hellman key exchange
def dh(B=None, p=None, g=None):
    sess = None
    p = p or \
        int('ffffffffffffffffc90fdaa22168c234c4c6628b80dc'
            '1cd129024e088a67cc74020bbea63b139b22514a0879'
            '8e3404ddef9519b3cd3a431b302b0a6df25f14374fe1'
            '356d6d51c245e485b576625e7ec6f44c42e9a637ed6b'
            '0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b'
            '1fe649286651ece45b3dc2007cb8a163bf0598da4836'
            '1c55d39a69163fa8fd24cf5f83655d23dca3ad961c62'
            'f356208552bb9ed529077096966d670c354e4abc9804'
            'f1746c08ca237327ffffffffffffffff', 16)
    g = g or 2
    a = random.randint(1, p)
    A = pow(g, a, p)
    if B is None:
        B, sess = dh(A)
    mysess = pow(B, a, p)
    if sess is not None:
        assert sess == mysess
    return (A, mysess)

#DH exchange bot
class DHBot(object):

    def set_other(self, other):
        self.other = other

    def begin(self):
        self.p = \
        int('ffffffffffffffffc90fdaa22168c234c4c6628b80dc'
            '1cd129024e088a67cc74020bbea63b139b22514a0879'
            '8e3404ddef9519b3cd3a431b302b0a6df25f14374fe1'
            '356d6d51c245e485b576625e7ec6f44c42e9a637ed6b'
            '0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b'
            '1fe649286651ece45b3dc2007cb8a163bf0598da4836'
            '1c55d39a69163fa8fd24cf5f83655d23dca3ad961c62'
            'f356208552bb9ed529077096966d670c354e4abc9804'
            'f1746c08ca237327ffffffffffffffff', 16)
        self.g = 2
        self.a = random.randint(1, self.p)
        self.A = pow(self.g, self.a, self.p)
        self.other.step1(self.p, self.g, self.A)

    def step1(self, p, g, A):
        self.p = p
        self.g = g
        self.A = A
        self.b = random.randint(1, p)
        self.B = pow(g, self.b, p)
        self.sess = pow(A, self.b, p)
        self.aes_key = sha1(i2a(self.sess))[:16]
        self.other.step2(self.B)

    def step2(self, B):
        self.sess = pow(B, self.a, self.p)
        self.aes_key = sha1(i2a(self.sess))[:16]
        self.msg = 'hello world ' + str(random.randint(1, 1000000))
        iv = randr(16)
        encr = aes_enc_cbc(self.aes_key, pad_to(self.msg, 16), iv) + iv
        print('A sent msg: "%s" with len %d' % (self.msg, len(self.msg)))
        self.other.step3(encr)

    def step3(self, encr):
        iv = encr[-16:]
        msg = aes_dec_cbc(self.aes_key, encr[:-16], iv)
        padlen = msg[-1]
        msg = msg[:-padlen]
        print('B received msg: "%s" with len %d' % (a2s(msg), len(msg)))
        iv2 = randr(16)
        encr2 = aes_enc_cbc(self.aes_key, pad_to(msg, 16), iv2) + iv2
        self.other.step4(encr2)

    def step4(self, encr):
        iv = encr[-16:]
        msg = aes_dec_cbc(self.aes_key, encr[:-16], iv)
        padlen = msg[-1]
        msg = msg[:-padlen]
        print('A received msg: "%s" with len %d' % (a2s(msg), len(msg)))

# DH adversary parent
class DHAdv(object):
    def set_others(self, ao, bo):
        self.ao = ao
        self.bo = bo

    def step1(self, *args):
        self.bo.step1(*args)

    def step2(self, *args):
        self.ao.step2(*args)

    def step3(self, *args):
        self.bo.step3(*args)

    def step4(self, *args):
        self.ao.step4(*args)

# DH adversary - change public numbers to p
class DHAdv1(DHAdv):
    def step1(self, p, g, A):
        self.p = p
        super(DHAdv1, self).step1(p, g, p)

    def step2(self, B):
        super(DHAdv1, self).step2(self.p)

    def step3(self, encr):
        sess = sha1([0])[:16]
        iv = encr[-16:]
        encrm = encr[:-16]
        msg = aes_dec_cbc(sess, encrm, iv)
        msg = msg[:-msg[-1]]
        print('Decrypted msg: "%s" with len %d' % (a2s(msg), len(msg)))
        super(DHAdv1, self).step3(encr)

# DH adversary - change g to 1
class DHAdv2(DHAdv):
    def step1(self, p, g, A):
        self.p = p
        super(DHAdv2, self).step1(p, 1, A)

    def step3(self, encr):
        sess = sha1([1])[:16]
        iv = encr[-16:]
        encrm = encr[:-16]
        msg = aes_dec_cbc(sess, encrm, iv)
        msg = msg[:-msg[-1]]
        print('Decrypted msg: "%s" with len %d' % (a2s(msg), len(msg)))
        super(DHAdv2, self).step3(encr)

# DH adversary - change g to p-1
class DHAdv3(DHAdv):
    def step1(self, p, g, A):
        self.p = p
        super(DHAdv3, self).step1(p, p-1, A)

    def step3(self, encr):
        sess = sha1([1])[:16]
        iv = encr[-16:]
        encrm = encr[:-16]
        msg = aes_dec_cbc(sess, encrm, iv)
        msg = msg[:-msg[-1]]
        print('Decrypted msg: "%s" with len %d' % (a2s(msg), len(msg)))
        super(DHAdv3, self).step3(encr)

# DH adversary - change g to p
class DHAdv4(DHAdv):
    def step1(self, p, g, A):
        self.p = p
        super(DHAdv4, self).step1(p, p, A)

    def step3(self, encr):
        sess = sha1([0])[:16]
        iv = encr[-16:]
        encrm = encr[:-16]
        msg = aes_dec_cbc(sess, encrm, iv)
        msg = msg[:-msg[-1]]
        print('Decrypted msg: "%s" with len %d' % (a2s(msg), len(msg)))
        super(DHAdv4, self).step3(encr)

# start a DH key exchange with an optional adversary
def do_dhke(adv=None):
    a = DHBot()
    b = DHBot()
    if adv:
        a.set_other(adv)
        b.set_other(adv)
        adv.set_others(a, b)
    else:
        a.set_other(b)
        b.set_other(a)
    a.begin()

# Secure Remote Password client/server
class SRPBot(object):
    def __init__(self, email, pw):
        self.N = \
        int('ffffffffffffffffc90fdaa22168c234c4c6628b80dc'
            '1cd129024e088a67cc74020bbea63b139b22514a0879'
            '8e3404ddef9519b3cd3a431b302b0a6df25f14374fe1'
            '356d6d51c245e485b576625e7ec6f44c42e9a637ed6b'
            '0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b'
            '1fe649286651ece45b3dc2007cb8a163bf0598da4836'
            '1c55d39a69163fa8fd24cf5f83655d23dca3ad961c62'
            'f356208552bb9ed529077096966d670c354e4abc9804'
            'f1746c08ca237327ffffffffffffffff', 16)
        self.g = 2
        self.k = 3
        self.email = email
        self.pw = pw

    def set_other(self, other):
        self.other = other

    def begin(self):
        self.salt = str(random.randint(0, 100000000000))
        xH = hashlib.sha256(self.salt + self.pw).hexdigest()
        x = int(xH, 16)
        self.v = pow(self.g, x, self.N)
        self.other.step1()

    def step1(self):
        self.a = random.randint(1, self.N)
        self.A = pow(self.g, self.a, self.N)
        self.other.step2(self.email, self.A)

    def step2(self, email, A):
        self.b = random.randint(1, self.N)
        self.A = A
        self.B = self.k*self.v + pow(self.g, self.b, self.N)
        uH = hashlib.sha256('%x%x' % (A, self.B)).hexdigest()
        self.u = int(uH, 16)
        self.other.step3(self.salt, self.B)

    def step3(self, salt, B):
        self.B = B
        uH = hashlib.sha256('%x%x' % (self.A, B)).hexdigest()
        self.u = int(uH, 16)
        xH = hashlib.sha256(salt + self.pw).hexdigest()
        x = int(xH, 16)
        S = pow(B - self.k*pow(self.g, x, self.N), self.a + self.u*x, self.N)
        K = hashlib.sha256(str(S)).hexdigest()
        self.other.step4(hmac_sha256(K, salt))

    def step4(self, mac):
        S = pow(self.A * pow(self.v, self.u, self.N), self.b, self.N)
        K = hashlib.sha256(str(S)).hexdigest()
        print(['Login failed', 'Login successful'][mac == hmac_sha256(K, self.salt)])

# Perform SRP exchange
def do_srp(client=None, server=None):
    server = server or SRPBot
    r = random.randint(1, 1000)
    pw = 'password %d' % r
    print('The password is: %s' % pw)
    a = server('email@email.com', pw)
    client = client or SRPBot
    b = client('email@email.com', pw)
    a.set_other(b)
    b.set_other(a)
    a.begin()

# SRP adversary - send 0 as A
class SRPAdv1(SRPBot):
    def __init__(self, *args):
        super(SRPAdv1, self).__init__(None, None)

    def step1(self):
        self.other.step2('email@email.com', 0)

    def step3(self, salt, B):
        K = hashlib.sha256(str('0')).hexdigest()
        self.other.step4(hmac_sha256(K, salt))

# SRP adversary - send N as A
class SRPAdv2(SRPBot):
    def __init__(self, *args):
        super(SRPAdv2, self).__init__(None, None)

    def step1(self):
        self.other.step2('email@email.com', self.N)

    def step3(self, salt, B):
        K = hashlib.sha256(str('0')).hexdigest()
        self.other.step4(hmac_sha256(K, salt))

# Simplified SRP
class SimpleSRP(SRPBot):
    def step2(self, email, A):
        self.b = random.randint(1, self.N)
        self.A = A
        self.B = pow(self.g, self.b, self.N)
        self.u = int(a2h(randr(16)), 16)
        self.other.step3(self.salt, self.B, self.u)

    def step3(self, salt, B, u):
        self.B = B
        self.u = u
        xH = hashlib.sha256(salt + self.pw).hexdigest()
        x = int(xH, 16)
        S = pow(B, self.a + self.u*x, self.N)
        K = hashlib.sha256(str(S)).hexdigest()
        self.other.step4(hmac_sha256(K, salt))

    def step4(self, mac):
        S = pow(self.A * pow(self.v, self.u, self.N), self.b, self.N)
        K = hashlib.sha256(str(S)).hexdigest()
        print(['Login failed', 'Login successful'][mac == hmac_sha256(K, self.salt)])

# Simplified SRP - adversary server that cracks pw
class SimpleSRPAdvServer(SimpleSRP):
    def __init__(self, email, pw):
        super(SimpleSRPAdvServer, self).__init__(email, '')

    def step4(self, mac):
        def pgen():
            for i in range(1000):
                yield 'password %d' % i
        for p in pgen():
            xH = hashlib.sha256(self.salt + p).hexdigest()
            x = int(xH, 16)
            self.v = pow(self.g, x, self.N)
            S = pow(self.A * pow(self.v, self.u, self.N), self.b, self.N)
            K = hashlib.sha256(str(S)).hexdigest()
            if mac == hmac_sha256(K, self.salt):
                print('Successfully cracked: %s' % p)
                break

# prime table primegen
def table_primegen(n=1000):
    r = range(2, n)
    for i in r:
        j = i*2
        while j < n:
            if j in r:
                r.remove(j)
            j += i
    return random.choice(r)

# Miller-Rabin primegen
mr_primegen = lambda: next(x for x in (random.randint(2**500, 2**600) for _ in iter(int, 1)) if pyprimes.miller_rabin(x))

# modular inverse
def invmod(b, a):
    s, so, t, to, r, ro = [0, 1, 1, 0, b, a]
    while r != 0:
        q = ro / r
        ro, r = [r, ro - q*r]
        so, s = [s, so - q*s]
        to, t = [t, to - q*t]
    if ro != 1:
        return None
    return to % a

# RSA implementation
def rsa(primegen=mr_primegen, e=3):
    while True:
        p = primegen()
        q = primegen()
        n = p*q
        et = (p-1)*(q-1)
        d = invmod(e, et)
        if d:
            break
    public = (e, n)
    private = (d, n)
    return (public, private)

# nth root of k
def iroot(n, k):
    u, s = n, n+1
    while u < s:
        s = u
        t = (k-1) * s + n / pow(s, k-1)
        u = t / k
    return s

# RSA CRT attack with small exp
def rsa_crt_attack():
    # only need public keys
    na = rsa(e=3)[0][1]
    nb = rsa(e=3)[0][1]
    nc = rsa(e=3)[0][1]
    # secret message
    m = random.randint(1000, min([na, nb, nc]))
    # encrypt message 3 times with RSA
    ca = pow(m, 3, na)
    cb = pow(m, 3, nb)
    cc = pow(m, 3, nc)
    # use Chinese Remainder Theorem to find c so that:
    # c = ca mod na, c = cb mod nb, c = cc mod nc
    N = na*nb*nc
    Na, Nb, Nc = N/na, N/nb, N/nc
    ta = ca*Na*invmod(Na, na)
    tb = cb*Nb*invmod(Nb, nb)
    tc = cc*Nc*invmod(Nc, nc)
    c = (ta+tb+tc) % N
    print "Message guessed:", iroot(c, 3) == m

# CCA2 attack on RSA
def rsa_oracle_attack():
    pub, prv = rsa(e=65537)
    m = random.randint(0, 100000000000)
    s = random.randint(2, 1000)
    c = pow(m, *pub)
    c2 = (c * pow(s, pub[0], pub[1])) % pub[1]
    m2 = pow(c2, *prv)
    guessed = (m2 * invmod(s, pub[1])) % pub[1]
    print "Message guessed:", guessed == m

# Bleichenbacher RSA signature forgery attack
def rsa_bleich_e3_attack():
    pub, _ = rsa(e=3)

    def validate_sig(m, sig, pub):
        cs = sha1(m)
        msig = pow(sig, *pub)
        a = i2a(msig)[1:]
        if a[0] != 0 or a[1] != 1:
            return 999
        i = 2
        while a[i] == 0xFF:
            i += 1
        if a[i] != 0 or a[i+1:i+9] != [12,34,56,78,90,91,23,45]:
            return 999
        same = [x[0] == x[1] for x in zip(cs, a[i+9:i+29])]
        return same.count(False)

    m = 'hi mom'
    sig = [1,0,1,0xFF,0,12,34,56,78,90,91,23,45] + sha1(m)
    diff = validate_sig(m, iroot(s2i(sig), 3), pub)
    while diff > 0:
        print "Different bytes: ", diff
        # add FF bytes until floor(cube_root(sig))**3
        # matches with the plaintext produced when validate_sig
        # tries to decrypt sig by applying the public key
        # which exps to the power of e=3
        # this way the private key is not needed for the signature
        sig += [0xFF]
        diff = validate_sig(m, iroot(s2i(sig), 3), pub)
    print "All same! Sig: ", sig

p_DSA = 0x800000000000000089e1855218a0e7dac38136ffafa72eda7859f2171e25e65eac698c1702578b07dc2a1076da241c76c62d374d8389ea5aeffd3226a0530cc565f3bf6b50929139ebeac04f48c3c84afb796d61e5a4f9a8fda812ab59494232c7d2b4deb50aa18ee9e132bfa85ac4374d7f9091abc3d015efc871a584471bb1
 
q_DSA = 0xf4f47f05794b256174bba6e9b396a7707e563c5b
 
g_DSA = 0x5958c9d3898b224b12672c0b98e06c60df923cb8bc999d119458fef538b8fa4046c8db53039db620c094c9fa077ef389b5322a559946a71903f990f1f7e0e025e2d7f7cf494aff1a0470f5b64c36b625a097f1651fe775323556fe00b3608c887892878480e99041be601a62166ca6894bdd41a7054ec89f756ba9fc95302291

# Sign message with DSA
def dsa_sign(m, p=p_DSA, q=q_DSA, g=g_DSA, k = random.randint(1, q_DSA-1)):
    x = random.randint(1, q-1)
    y = pow(g, x, p)
    r = pow(g, k, p) % q
    s = (invmod(k, q) * (sha1i(m) + x*r)) % q
    return (r, s, y)

# Verify message with DSA
def dsa_verify(m, r, s, y, p=p_DSA, q=q_DSA, g=g_DSA):
    w = invmod(s, q)
    u1 = (sha1i(m) * w) % q
    u2 = (r * w) % q
    v = ((pow(g, u1, p) * pow(y, u2, p)) % p) % q
    return r == v

# Find secret key x from k and a signature
def dsa_get_secret(m, k, r, s, y=None, p=p_DSA, q=q_DSA, g=g_DSA):
    x = (s*k - sha1i(m)) * invmod(r, q) % q
    if y and y != pow(g, x, p):
        return None
    return x

# Find k and secret key of DSA from 2 messages with the same k
def dsa_find_k(m1, s1, m2, s2, g, p, q):
    d1 = (m1 - m2) % q
    d2 = (s1 - s2) % q
    k = (d1 * invmod(d2, q)) % q
    r = pow(g, k, p) % q
    x = ((s1 * k - m1) * invmod(r, q)) % q
    return (k, x)

# RSA last bit decryption oracle
def rsa_last_bit_oracle(priv_key):
    def oracle(x):
        return pow(x, *priv_key) & 1
    return oracle

# Decrypt RSA encrypted message using last bit oracle
def rsa_decrypt_lastbit(ctxt, oracle, e, n):
    lo = 0
    hi = n-1
    mult = pow(2, e, n)
    while lo < hi:
        print(lo, hi)
        ctxt = (ctxt*mult) % n
        # if by doubling, the last bit is 1 because of the modulus with n which is odd, this means 2*ctxt > n, otherwise < n 
        if oracle(ctxt) == 1:
            lo=(hi+lo)/2 + 1
        else:
            hi=(hi+lo)/2
    return lo, hi

# RSA PKCS1v1.5 padding oracle
def pkcs15_oracle(l, d, n):
    def oracle(ctxt):
        ptxt = i2a(pow(ctxt, d, n))
        ptxt = [0]*(l - len(ptxt)) + ptxt
        return ptxt[:2] == [0, 2]
    return oracle


# variable bit primegen
mr_primegen_bits = lambda bits: lambda: next(x for x in (random.randint(2**(bits-1), 2**bits) for _ in iter(int, 1)) if pyprimes.miller_rabin(x))

# Division round up
divup = lambda n, d: (n + d - 1) / d

# Bleichenbacher98 attack with RSA pkcs1.5 padding oracle
def rsa_bleich_pkcs_attack(ctxt, oracle, k, e, n):
    B = 2**(8*(k-2))
    cs = 0
    while not oracle(cs):
        s0 = random.randint(2, n)
        cs = (ctxt * pow(s0, e, n)) % n
    c0 = cs
    M = [[(2*B, 3*B-1)]]
    i = 1
    s = []
    
    while True:
        if i == 1:
            s1 = divup(n, 3*B)
            cs = (c0 * pow(s1, e, n)) % n
            while not oracle(cs):
                s1 += 1
                cs = (c0 * pow(s1, e, n)) % n
            s.append(s1)
        elif len(M[-1]) > 1:
            sn = s[-1] + 1
            while not oracle((c0 * pow(sn, e, n)) % n):
                sn += 1
            s.append(sn)
        else:
            a, b = M[-1][0]
            sl = s[-1]
            r = divup(2 * (b * sl - 2 * B), n)
            sn = divup(2*B + r*n, b)
            cs = 0
            while True:
                cs = (c0 * pow(sn, e, n)) % n
                if oracle(cs):
                    break
                elif sn * a < 3*B + r*n:
                    sn += 1
                else:
                    r += 1
                    sn = divup(2*B + r*n, b)
            s.append(sn)
        Mn = []
        sc = s[-1]
        for Ml in M[-1]:
            a, b = Ml
            for r in range(divup(a * sc - 3*B + 1, n), (b * sc - 2 * B) / n + 1):
                Mstart = max(a, divup(2*B + r*n, sc))
                Mend = min(b, (3*B - 1 + r*n) / sc)
                Mn.append((Mstart, Mend))
        M.append(Mn)
        if len(Mn) == 1 and Mn[0][0] == Mn[0][1]:
            a = Mn[0][0]
            m = (a * invmod(s0, n)) % n
            print "Found m =", m
            return m
        i += 1


# Demonstrate above attack
def do_bleichenbacher98_attack(bits):
    #Good bits values: 256 (easy), 768 (harder)
    pub = (0, 0)
    while len(bin(pub[1])) - 2 != bits:
        pub, prv = rsa(mr_primegen_bits(bits/2))
    byte_len = bits/8
    ptxt = pkcs15('kick it, CC', byte_len)
    ctxt = pow(s2i(ptxt), *pub)
    oracle = pkcs15_oracle(byte_len, *prv)
    m = rsa_bleich_pkcs_attack(ctxt, oracle, byte_len, *pub)
    m = i2s(m)
    print "Recovered message:", m[(m.find('\x00') + 1):]

# CBC Mac impl
cbc_mac = lambda msg, key, iv: aes_enc_cbc(key, pad_to(msg, 16), iv)[-16:]

def verify_cbc_mac_oracle(key):
    def verify(msg, mac, iv=[0]):
        return cbc_mac(msg, key, iv) == mac
    return verify

# attack on CBC_MAC by controlling IV
def attack_cbc_mac():
    key = randr(16)
    iv = randr(16)
    original = "from=1000&to=1001&amount=1000000"
    mac = cbc_mac(original, key, iv)
    oracle = verify_cbc_mac_oracle(key)
    new_iv = xor(xor("from=1000&to=1001&amount=1000000", "from=6666&to=1001&amount=1000000"), iv)
    assert oracle("from=6666&to=1001&amount=1000000", mac, new_iv)

# attack on cbc_mac using static IV
def attack_cbc_mac_staticiv():
    key = randr(16)
    original = "from=1000&txlist=100:123;200:456"
    mac = cbc_mac(original, key, [0])
    oracle = verify_cbc_mac_oracle(key)
    assert(oracle(original, mac))
    forged = "from=6666&txlist=6666:123"
    forged_mac = cbc_mac(forged, key, [0])
    forged = pad_to(forged, 16)
    forged2 = forged + xor(s2a(original[:16]), forged_mac) + s2a(original[16:])
    assert cbc_mac(forged2, key, [0]) == mac
    forged2 = pad_to(forged2, 16) + s2a(';6666:1000000')
    spoofed_mac = cbc_mac(forged2, key, [0])
    forged_original = pad_to(original, 16) + s2a(';6666:1000000')
    assert oracle(forged_original, spoofed_mac)
    assert a2s(forged2).startswith('from=6666')
    print(map(chr, forged_original))

# 2nd preimage attack on cbc_mac
def cbc_mac_2nd_preimg():
    msg = "alert('MZA who was that?');\n"
    key = 'YELLOW SUBMARINE'
    spoof = "alert('Ayo, the Wu is back!');\n//"
    spoof_mac_1 = cbc_mac(spoof, key, [0])
    spoof = pad_to(spoof, 16) + xor(spoof_mac_1, s2a(msg[:16])) + s2a(msg[16:])
    assert cbc_mac(spoof, key, [0]) == cbc_mac(msg, key, [0])
    print(spoof)

# Stream cipher encrypted compressed ptxt length oracle
def breach_oracle_stream(content):
    ptxt = "POST / HTTP/1.1\nHost: hapless.com\n"\
    "Cookie: sessionid=TmV2ZXIgcmV2ZWFsIHRoZSBXdS1UYW5nIFNlY3JldCE=\n"\
    "Content-Length: {}\n{}".format(len(content), content)
    comp = zlib.compress(ptxt)
    iv = randr(24)
    key = randr(32)
    ctxt = salsa20.XSalsa20_xor(comp, a2s(iv), a2s(key))
    return len(ctxt)

# start HMAC server
def start_hmac_server():
    from flask import Flask, request
    app = Flask(__name__)
    hmac_key = randr(64)

    @app.route('/hmac')
    def hmac():
        with open(request.args.get('file')) as f:
            x = f.read()
        signature = h2a(request.args.get('signature'))
        s1 = hmac_sha1(hmac_key, x)
        for i, j in zip(signature+[0]*30, s1):
            if i != j:
                return ('no', 500)
            time.sleep(0.005)
        return ('ok', 200)

    @app.route('/')
    def ind():
        with open(request.args.get('file')) as f:
            x = f.read()
        s1 = hmac_sha1(hmac_key, x)
        return a2h(s1)

    app.run(port=8081, processes=10)

# Guess sessionid using an attack similar to BREACH on above oracle
def breach_attack_stream():
    s = 'sessionid='
    for i in range(22):
        best = 100000
        bestc = ''
        for l in product(string.ascii_letters + string.digits + '=', repeat=2):
            l = ''.join(l)
            if breach_oracle_stream(s+l) < best:
                best = breach_oracle_stream(s+l)
                bestc = l
        s += bestc
        print(s)

# Block cipher encrypted compressed ptxt length oracle
def breach_oracle_block(content):
    ptxt = "POST / HTTP/1.1\nHost: hapless.com\n"\
    "Cookie: sessionid=TmV2ZXIgcmV2ZWFsIHRoZSBXdS1UYW5nIFNlY3JldCE=\n"\
    "Content-Length: {}\n{}".format(len(content), content)
    comp = zlib.compress(ptxt)
    iv = randr(16)
    key = randr(16)
    ctxt = aes_enc_cbc(a2s(key), pad_to(comp, 16), a2s(iv))
    return len(ctxt)

# Guess sessionid using an attack similar to BREACH on above oracle
def breach_attack_block():
    s = 'sessionid='
    prefixidx = 0
    i = 0
    while i < 44:
        best = 100000
        worst = 0
        bestc = ''
        for l in string.ascii_letters + string.digits + '=':
            cost = breach_oracle_block(s+l) 
            if cost < best:
                best = cost
                bestc = l
            if cost > worst:
                worst = cost
        if best == worst:
            s = string.printable[prefixidx] + s
            prefixidx += 1
            continue
        s = s[prefixidx:]
        prefixidx = 0
        s += bestc
        i += 1
        print(s)

# Bad 16bit MD hash function
def MDbad(x, length, H=None):
    H = H or [10*(i+1) for i in range(length)]
    iv = range(16)
    for i in x:
        H = aes_enc_cbc(pad_to(H, 16), pad_to([i], 16), iv)[-length:]
    return H

# Find exponentially (with depth) many collisions
def MDbad_gen_col(depth, H=None, output=True):
    print "Depth", depth
    while True:
        a = randr(3)
        b = randr(3)
        if a != b and MDbad(a,2,H) == MDbad(b,2,H):
            if output:
                print "Collided", a, b, "with hash", MDbad(a,2,H), "and seed", H
            if depth == 1:
                yield a
                yield b
                return
            else:
                for n in MDbad_gen_col(depth-1, MDbad(a,2,H), output):
                    yield a + n
                    yield b + n
                return

# Find collisions of concat of MDbad with len 2 and MDbad with len 5
def MDbad_concat_gen_col():
    # birthday problem says we have an 83% chance to find a 5 byte collision in 2000000 attempts
    # log2(2000000) ~= 21
    # Generate many easy collisions for MDbad with len 2 with above func and use these
    # to find a collision for len 5 to decrease complexity significantly
    # This proves concat of collision unsafe funcs to be also collision unsafe
    prev = []
    prevset = set([])
    for x in MDbad_gen_col(21, None, False):
        hx = MDbad(x, 5)
        if tuple(hx) in prevset:
            for y, hy in prev:
                if hx == hy:
                    assert MDbad(pad_to(x,16), 2) + MDbad(pad_to(x,16), 5) == MDbad(pad_to(y,16), 2) + MDbad(pad_to(y,16), 5)
                    print "Found collision", x, y
                    return (x, y)
        prev.append((x, hx))
        prevset.add(tuple(hx))

# Second preimage attack on MDbad
def MDbad_expendable_msgs():
    # Generate disposable message so we can easily fill in the first n blocks of the hash
    # and get the same result
    k = 7
    shorts = []
    longs = []
    prevstate = None
    for i in range(1, k+1):
        a = randr(3*(2**(k-i)))
        Ha = MDbad(a, 2, prevstate)
        while True:
            a2 = randr(3)
            b = randr(3)
            if MDbad(a2, 2, Ha) == MDbad(b, 2, prevstate):
                shorts.append(b)
                longs.append(a+a2)
                prevstate = MDbad(b, 2, prevstate)
                break
    targetmsg = pad_to(randr(3 * (2**k)), 16)
    targetlast = None
    interms = []
    for i in range(0, len(targetmsg), 3):
        targetlast = MDbad(targetmsg[i:i+3], 2, targetlast)
        interms.append(targetlast)
    bridge = None
    # Find a bridge block from our final state to one of the intermediate states of the target hash
    while True:
        bridge = randr(3)
        if MDbad(bridge, 2, prevstate) in interms:
            break
    idx = interms.index(MDbad(bridge, 2, prevstate))
    # The collision is a combination of shorts and longs that adds up to `idx` length
    wherelongs = bin(idx-7)[2:]
    while len(wherelongs) < 7:
        wherelongs = '0'+wherelongs
    prefix = [shorts[i] if wherelongs[i] == '0' else longs[i] for i in range(7)]
    prefix = reduce(lambda x, y: x+y, prefix)
    fakemsg = prefix + bridge + targetmsg[(idx+1)*3:]
    assert fakemsg != targetmsg and len(fakemsg) == len(targetmsg) and MDbad(fakemsg, 2) == MDbad(targetmsg, 2)
    print "Found collision (both have MDbad = {})".format(MDbad(fakemsg, 2)), fakemsg, targetmsg
