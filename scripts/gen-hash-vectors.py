#!/usr/bin/env python3
"""Generate internal/passhash/testdata/vectors.json: password hash vectors for
the Auth0 bulk-import formats.

Every vector is computed here with Python's standard library (hashlib, hmac,
base64, crypt); none is copied from Auth0's documentation. Run it with Python
3.12 (bcrypt comes from the libc-backed `crypt` module, removed in 3.13):

    podman run --rm -v $PWD:/w:Z -w /w docker.io/library/python:3.12-slim \
        python3 -I scripts/gen-hash-vectors.py

MD4 is not in hashlib on OpenSSL 3, so a small pure-Python MD4 is included and
checked against the RFC 1320 test vectors before use.

password.encoding follows Node's Buffer.from(s, enc), which is what Auth0's
documented encodings are. Python's own codecs differ: 'latin1' raises for a
character above U+00FF and 'ascii' raises for any non-ASCII one, whereas Node
keeps the low 8 bits of every UTF-16 code unit for ascii, latin1 and binary.
node_bytes() below emulates Node explicitly instead of using those codecs.

Later tasks append their algorithms (pbkdf2, scrypt, argon2, whirlpool) to the
same file; "task" says which task's verifier a vector exercises.
"""
import base64
import hashlib
import hmac
import json
import struct
import sys
import warnings

warnings.simplefilter("ignore")
import crypt  # noqa: E402  (Python <= 3.12)


# ---- MD4 (RFC 1320) ---------------------------------------------------------
class MD4:
    digest_size = 16
    block_size = 64
    name = "md4"

    def __init__(self, data=b""):
        self.buf = b""
        self.update(data)

    def update(self, data):
        self.buf += bytes(data)

    def copy(self):
        c = MD4()
        c.buf = self.buf
        return c

    def hexdigest(self):
        return self.digest().hex()

    def digest(self):
        msg = self.buf
        n = len(msg)
        msg += b"\x80" + b"\x00" * ((55 - n) % 64) + struct.pack("<Q", n * 8 & (2**64 - 1))
        a, b, c, d = 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476
        m32 = 0xFFFFFFFF

        def rol(x, s):
            x &= m32
            return ((x << s) | (x >> (32 - s))) & m32

        for off in range(0, len(msg), 64):
            x = struct.unpack("<16I", msg[off:off + 64])
            aa, bb, cc, dd = a, b, c, d
            for i in range(16):
                k, s = i, (3, 7, 11, 19)[i % 4]
                f = (b & c) | (~b & d)
                a, b, c, d = d, rol(a + f + x[k], s), b, c
            for i in range(16):
                k, s = (i % 4) * 4 + i // 4, (3, 5, 9, 13)[i % 4]
                f = (b & c) | (b & d) | (c & d)
                a, b, c, d = d, rol(a + f + x[k] + 0x5A827999, s), b, c
            order = (0, 8, 4, 12, 2, 10, 6, 14, 1, 9, 5, 13, 3, 11, 7, 15)
            for i in range(16):
                k, s = order[i], (3, 9, 11, 15)[i % 4]
                f = b ^ c ^ d
                a, b, c, d = d, rol(a + f + x[k] + 0x6ED9EBA1, s), b, c
            a, b, c, d = (a + aa) & m32, (b + bb) & m32, (c + cc) & m32, (d + dd) & m32
        return struct.pack("<4I", a, b, c, d)


for msg, want in ((b"", "31d6cfe0d16ae931b73c59d7e0c089c0"),
                  (b"a", "bde52cb31de33e46245e05fbdbd6fb24"),
                  (b"abc", "a448017aaf21d8525fc10ae87aa6729d"),
                  (b"message digest", "d9130a8164549fe818874806e1c7014b")):
    assert MD4(msg).hexdigest() == want, "MD4 self-check failed"

# ---- helpers ----------------------------------------------------------------
DIGESTS = {
    "md4": MD4,
    "md5": hashlib.md5,
    "sha1": hashlib.sha1,
    "sha224": hashlib.sha224,
    "sha256": hashlib.sha256,
    "sha384": hashlib.sha384,
    "sha512": hashlib.sha512,
    "ripemd160": lambda d=b"": hashlib.new("ripemd160", d),
}


def node_bytes(s, enc):
    """Buffer.from(s, enc) for the password encodings Auth0 documents."""
    if enc == "utf8":
        return s.encode("utf-8")
    units = s.encode("utf-16-le")
    if enc in ("utf16le", "ucs2"):
        return units
    if enc in ("ascii", "latin1", "binary"):
        # Low 8 bits of each UTF-16 code unit, as Node does.
        return bytes(units[i] for i in range(0, len(units), 2))
    raise ValueError(enc)


def enc_out(raw, enc):
    return raw.hex() if enc == "hex" else base64.b64encode(raw).decode()


def salt_bytes(salt):
    if salt is None:
        return b"", None
    return {"hex": bytes.fromhex, "base64": base64.b64decode,
            "utf8": lambda v: v.encode()}[salt["encoding"]](salt["value"]), salt.get("position")


def joined(salt, pw):
    sb, pos = salt_bytes(salt)
    return sb + pw if pos in (None, "prefix") else pw + sb


VECTORS = []


def add(name, spec, password, task="3"):
    VECTORS.append({"name": name, "task": task, "spec": spec, "password": password, "match": True})
    VECTORS.append({"name": name + "/wrong", "task": task, "spec": spec,
                    "password": "x" + password, "match": False})


def spec_digest(alg, value, enc, salt=None, pwenc=None, **extra):
    s = {"algorithm": alg, "hash": {"value": value, "encoding": enc}}
    s["hash"].update(extra)
    if salt:
        s["salt"] = salt
    if pwenc:
        s["password"] = {"encoding": pwenc}
    return s


PW = "Pa55w0rd!"
SALTS = {
    "none": None,
    "prefix-utf8": {"value": "NaCl-pre", "encoding": "utf8", "position": "prefix"},
    "suffix-utf8": {"value": "NaCl-suf", "encoding": "utf8", "position": "suffix"},
    "suffix-hex": {"value": "00ff10ab", "encoding": "hex", "position": "suffix"},
    "prefix-base64": {"value": "c2FsdHktYmFzZTY0", "encoding": "base64", "position": "prefix"},
    "default-position": {"value": "dflt", "encoding": "utf8"},
}

# ---- plain digests ----------------------------------------------------------
for alg in ("md4", "md5", "sha1", "sha256", "sha512"):
    for hexenc in ("hex", "base64"):
        for sname, salt in SALTS.items():
            raw = DIGESTS[alg](joined(salt, PW.encode())).digest()
            add(f"{alg}/{hexenc}/salt-{sname}", spec_digest(alg, enc_out(raw, hexenc), hexenc, salt), PW)

# ---- password encodings (Review Focus 3) -------------------------------------
ENC_PASSWORDS = {
    "ascii-only": "plain",
    "latin1-e-acute": "héllo",
    "above-ff": "euro€!",
    "non-bmp": "smile\U0001F600",
    "cjk": "漢字",
}
for pwenc in ("ascii", "utf8", "utf16le", "ucs2", "latin1", "binary"):
    for pname, pw in ENC_PASSWORDS.items():
        for sname in ("none", "suffix-utf8"):
            salt = SALTS[sname]
            raw = hashlib.sha256(joined(salt, node_bytes(pw, pwenc))).digest()
            add(f"password-encoding/{pwenc}/{pname}/salt-{sname}",
                spec_digest("sha256", raw.hex(), "hex", salt, pwenc), pw)

# ---- hmac -------------------------------------------------------------------
KEYS = {
    "utf8": {"value": "s3cret key", "encoding": "utf8"},
    "default-encoding": {"value": "plainkey"},
    "hex": {"value": "0a0b0c0d0e0f", "encoding": "hex"},
    "base64": {"value": "a2V5LWJhc2U2NA==", "encoding": "base64"},
}
KEYRAW = {"utf8": b"s3cret key", "default-encoding": b"plainkey",
          "hex": bytes.fromhex("0a0b0c0d0e0f"), "base64": b"key-base64"}
for dig, ctor in DIGESTS.items():
    for kname, key in KEYS.items():
        for sname in ("none", "suffix-utf8", "prefix-hex"):
            salt = {"none": None, "prefix-hex": {"value": "dead", "encoding": "hex", "position": "prefix"},
                    "suffix-utf8": SALTS["suffix-utf8"]}[sname]
            mac = hmac.new(KEYRAW[kname], joined(salt, PW.encode()), ctor).digest()
            hexenc = "hex" if kname in ("utf8", "hex") else "base64"
            spec = spec_digest("hmac", enc_out(mac, hexenc), hexenc, salt, digest=dig, key=key)
            add(f"hmac/{dig}/key-{kname}/salt-{sname}", spec, PW)

# ---- ldap (RFC 2307) -----------------------------------------------------------
LDAP_SALT = bytes.fromhex("0123456789abcdef")
for scheme, ctor in (("MD5", hashlib.md5), ("SHA", hashlib.sha1), ("SHA256", hashlib.sha256),
                     ("SHA384", hashlib.sha384), ("SHA512", hashlib.sha512)):
    unsalted = "{%s}%s" % (scheme, base64.b64encode(ctor(PW.encode()).digest()).decode())
    add(f"ldap/{scheme}", {"algorithm": "ldap", "hash": {"value": unsalted, "encoding": "utf8"}}, PW)
    sch = "S" + scheme
    salted = "{%s}%s" % (sch, base64.b64encode(ctor(PW.encode() + LDAP_SALT).digest() + LDAP_SALT).decode())
    add(f"ldap/{sch}", {"algorithm": "ldap", "hash": {"value": salted, "encoding": "utf8"}}, PW)
    # lower-case scheme name, as RFC 2307 schemes are case-insensitive
    add(f"ldap/{sch}/lowercase",
        {"algorithm": "ldap", "hash": {"value": "{%s}%s" % (sch.lower(), salted.split("}", 1)[1]),
                                       "encoding": "utf8"}}, PW)

# ---- bcrypt -----------------------------------------------------------------------
B64 = "abcdefghijklmnopqrstuu"  # 22 salt characters


def bcrypt_hash(minor, pw_bytes):
    return crypt.crypt(pw_bytes.decode("latin1"), "$2%s$10$%s" % (minor, B64))


for minor in ("a", "b", "y"):
    h = bcrypt_hash(minor, PW.encode())
    assert h.startswith("$2%s$10$" % minor) and len(h) == 60, h
    add(f"bcrypt/2{minor}", {"algorithm": "bcrypt", "hash": {"value": h, "encoding": "utf8"}}, PW)
for sname in ("prefix-utf8", "suffix-utf8"):
    salt = SALTS[sname]
    h = bcrypt_hash("b", joined(salt, PW.encode()))
    add(f"bcrypt/salt-{sname}",
        {"algorithm": "bcrypt", "hash": {"value": h, "encoding": "utf8"}, "salt": salt}, PW)
# 70-byte password + 10-byte suffix salt: bcrypt sees only the first 72 bytes
long_pw = ("0123456789" * 7)
long_salt = {"value": "SUFFIXSALT", "encoding": "utf8", "position": "suffix"}
h = bcrypt_hash("b", (long_pw.encode() + b"SUFFIXSALT")[:72])
add("bcrypt/long-input-truncated",
    {"algorithm": "bcrypt", "hash": {"value": h, "encoding": "utf8"}, "salt": long_salt}, long_pw)

out = "internal/passhash/testdata/vectors.json"
with open(out, "w") as f:
    json.dump(VECTORS, f, indent=1)
    f.write("\n")
