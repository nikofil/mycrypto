import operator
import string
import time
import struct
import random
import hashlib
import requests
import Crypto.Cipher.AES
import pyprimes
import sha1 as _sha1
import md4 as _md4

from base64 import *
from itertools import *

freq = {'e': 12.70, 't': 9.06, 'a': 8.17, 'o': 7.51, 'i': 6.97, 'n': 6.75, 's': 6.33, 'h': 6.09, 'r': 5.99, 'd': 4.25, 'l': 4.03, 'c': 2.78, 'u': 2.76, 'm': 2.41, 'w': 2.36, 'f': 2.23, 'g': 2.02, 'y': 1.97, 'p': 1.93, 'b': 1.29, 'v': 0.98, 'k': 0.77, 'j': 0.15, 'x': 0.15, 'q': 0.10, 'z': 0.07}

# str to int array
s2a = lambda x: [ord(x) for x in x]
# int array to str
a2s = lambda a: ''.join([chr(x) for x in a])

# start HMAC server
if __name__ == '__main__':
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
i2a = lambda x: [int(a, 16) for a in break_pieces(('%x' % x).zfill(2), 2)]
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
