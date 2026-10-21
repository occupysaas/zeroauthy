#!/usr/bin/env python3
"""Generate internal/passhash/testdata/vectors-kdf.json: vectors for pbkdf2,
scrypt, argon2 and hmac with whirlpool (Plan 18, Task 4).

Unlike gen-hash-vectors.py this runs on the host, because the reference tools
are host binaries and the python:3.12-slim image used for bcrypt has neither
the argon2 CLI at a useful version nor OpenSSL's mdc2:

    python3 -I scripts/gen-hash-vectors-kdf.py

Reference implementations, none taken from Auth0's documentation:
  pbkdf2   `openssl kdf PBKDF2` (legacy provider, so whirlpool and mdc2 and
           every OpenSSL alias name work), cross-checked against Python's
           hashlib.pbkdf2_hmac where hashlib has the digest
  scrypt   hashlib.scrypt
  argon2   the `argon2` command line tool (reference C implementation)
  hmac     `openssl mac HMAC` with the whirlpool digest
The vectors use the same shape as vectors.json.
"""
import base64
import hashlib
import json
import subprocess

PW = "Pa55w0rd!"
OSSL = ["-provider", "legacy", "-provider", "default"]
VECTORS = []


def add(name, spec, password):
    VECTORS.append({"name": name, "task": "4", "spec": spec, "password": password, "match": True})
    VECTORS.append({"name": name + "/wrong", "task": "4", "spec": spec,
                    "password": "x" + password, "match": False})


def b64u(raw):
    return base64.b64encode(raw).decode().rstrip("=")


def run(cmd, data=b""):
    return subprocess.run(cmd, input=data, capture_output=True, check=True).stdout


# ---- pbkdf2 -------------------------------------------------------------------
def openssl_pbkdf2(digest, pw, salt, iters, keylen):
    return run(["openssl", "kdf", *OSSL, "-keylen", str(keylen), "-kdfopt", "digest:" + digest,
                "-kdfopt", "hexpass:" + pw.hex(), "-kdfopt", "hexsalt:" + salt.hex(),
                "-kdfopt", "iter:%d" % iters, "-binary", "PBKDF2"])


SALT = bytes.fromhex("00112233445566778899aabbccddeeff")
BASE = {"md4": ["md4", "rsa-md4", "md4withrsaencryption"],
        "md5": ["md5", "rsa-md5", "md5withrsaencryption", "ssl3-md5"],
        "sha1": ["sha1", "rsa-sha1", "sha1withrsaencryption", "ssl3-sha1", "rsa-sha1-2"],
        "sha224": ["sha224", "rsa-sha224", "sha224withrsaencryption"],
        "sha256": ["sha256", "rsa-sha256", "sha256withrsaencryption"],
        "sha384": ["sha384", "rsa-sha384", "sha384withrsaencryption"],
        "sha512": ["sha512", "rsa-sha512", "sha512withrsaencryption"],
        "ripemd160": ["ripemd160", "rmd160", "ripemd", "rsa-ripemd160", "ripemd160withrsa"],
        "whirlpool": ["whirlpool"],
        "mdc2": ["mdc2", "rsa-mdc2", "mdc2withrsa"]}
for base, names in BASE.items():
    for name in names:
        # OpenSSL 3's provider fetch knows only some alias spellings (Node's
        # legacy EVP name table knows them all): an alias it rejects is
        # computed with the base digest it names.
        try:
            key = openssl_pbkdf2(name, PW.encode(), SALT, 1000, 32)
        except subprocess.CalledProcessError:
            print("openssl rejects alias %s: using %s" % (name, base))
            key = openssl_pbkdf2(base, PW.encode(), SALT, 1000, 32)
        if base in hashlib.algorithms_available and base not in ("md4", "ripemd160"):
            assert key == hashlib.pbkdf2_hmac(base, PW.encode(), SALT, 1000, 32), name
        phc = "$pbkdf2-%s$i=1000,l=32$%s$%s" % (name, b64u(SALT), b64u(key))
        add("pbkdf2/%s" % name, {"algorithm": "pbkdf2", "hash": {"value": phc, "encoding": "utf8"}}, PW)

# defaults: no parameters at all means i=100000, l=64
key = openssl_pbkdf2("sha256", PW.encode(), SALT, 100000, 64)
assert key == hashlib.pbkdf2_hmac("sha256", PW.encode(), SALT, 100000, 64)
phc = "$pbkdf2-sha256$$%s$%s" % (b64u(SALT), b64u(key))
add("pbkdf2/defaults-empty-params", {"algorithm": "pbkdf2", "hash": {"value": phc, "encoding": "utf8"}}, PW)
phc = "$pbkdf2-sha256$i=100000$%s$%s" % (b64u(SALT), b64u(key))
add("pbkdf2/default-l", {"algorithm": "pbkdf2", "hash": {"value": phc, "encoding": "utf8"}}, PW)
# non-ASCII password, a short key and a padded/URL-safe-looking salt encoding
key = hashlib.pbkdf2_hmac("sha512", "pässwörd€".encode(), b"\xfb\xff\xfe\xfa", 777, 20)
salt_url = base64.urlsafe_b64encode(b"\xfb\xff\xfe\xfa").decode()  # "-__--g==" style
phc = "$pbkdf2-sha512$i=777,l=20$%s$%s" % (salt_url, b64u(key))
add("pbkdf2/utf8-password-urlsafe-padded-salt",
    {"algorithm": "pbkdf2", "hash": {"value": phc, "encoding": "utf8"}}, "pässwörd€")

# ---- scrypt -------------------------------------------------------------------
def scrypt_vec(name, pw, salt, salt_spec, n, r, p, keylen, out_enc, spec_extra=None, pwraw=None):
    raw = hashlib.scrypt(pwraw if pwraw is not None else pw.encode(), salt=salt, n=n, r=r, p=p,
                         dklen=keylen, maxmem=512 * 1024 * 1024)
    spec = {"algorithm": "scrypt",
            "hash": {"value": raw.hex() if out_enc == "hex" else base64.b64encode(raw).decode(),
                     "encoding": out_enc},
            "keylen": keylen}
    if n != 16384:
        spec["cost"] = n
    if r != 8:
        spec["blockSize"] = r
    if p != 1:
        spec["parallelization"] = p
    if salt_spec:
        spec["salt"] = salt_spec
    spec.update(spec_extra or {})
    add(name, spec, pw)


scrypt_vec("scrypt/defaults-hex", PW, b"NaCl-scrypt", {"value": "NaCl-scrypt", "encoding": "utf8"},
           16384, 8, 1, 32, "hex")
scrypt_vec("scrypt/base64-hexsalt", PW, bytes.fromhex("a1b2c3d4e5f6"),
           {"value": "a1b2c3d4e5f6", "encoding": "hex"}, 1024, 8, 1, 64, "base64")
scrypt_vec("scrypt/base64salt-r4-p2", PW, b"base64-salt",
           {"value": base64.b64encode(b"base64-salt").decode(), "encoding": "base64"}, 2048, 4, 2, 24, "hex")
scrypt_vec("scrypt/no-salt", PW, b"", None, 1024, 8, 1, 32, "hex")
scrypt_vec("scrypt/utf16le-password", "pw€", b"s", {"value": "s"}, 1024, 8, 1, 32, "hex",
           {"password": {"encoding": "utf16le"}}, pwraw="pw€".encode("utf-16-le"))

# ---- argon2 -------------------------------------------------------------------
def argon2_vec(name, variant, salt, t, kib, p, length, pw=PW, version=None):
    cmd = ["argon2", salt, "-" + variant[len("argon2"):] if variant != "argon2i" else "-i",
           "-t", str(t), "-k", str(kib), "-p", str(p), "-l", str(length), "-e"]
    if version:
        cmd += ["-v", version]
    enc = run(cmd, pw.encode()).decode().strip()
    assert enc.startswith("$" + variant + "$"), enc
    add(name, {"algorithm": "argon2", "hash": {"value": enc, "encoding": "utf8"}}, pw)
    return enc


for variant in ("argon2i", "argon2d", "argon2id"):
    argon2_vec("argon2/%s" % variant, variant, "somesaltsomesalt", 2, 64, 1, 32)
    argon2_vec("argon2/%s/p4-m256" % variant, variant, "pepperpepper", 3, 256, 4, 24)
argon2_vec("argon2/argon2id/utf8-password", "argon2id", "unicodesalt1234", 2, 128, 2, 32, pw="pässwörd€")
# Argon2 1.0 (`-v 10`): the CLI writes v=16; a string without v= is read as 1.0
for variant in ("argon2i", "argon2d", "argon2id"):
    for t, kib, p in ((2, 64, 1), (3, 256, 2)):  # t>1: the pass that differs from 1.3
        enc = argon2_vec("argon2/%s/v16/t%d-p%d" % (variant, t, p), variant, "oldversionsalt", t, kib, p, 32,
                         version="10")
        assert "$v=16$" in enc, enc
        add("argon2/%s/no-v/t%d-p%d" % (variant, t, p),
            {"algorithm": "argon2", "hash": {"value": enc.replace("$v=16$", "$"), "encoding": "utf8"}}, PW)

# ---- hmac with whirlpool -------------------------------------------------------
KEYS = {"utf8": ({"value": "s3cret key", "encoding": "utf8"}, b"s3cret key"),
        "hex": ({"value": "0a0b0c0d0e0f", "encoding": "hex"}, bytes.fromhex("0a0b0c0d0e0f")),
        "base64": ({"value": "a2V5LWJhc2U2NA==", "encoding": "base64"}, b"key-base64"),
        # longer than the 64-byte block: the key is hashed first
        "long": ({"value": "k" * 100, "encoding": "utf8"}, b"k" * 100)}
SALTS = {"none": (None, b"", None),
         "suffix-utf8": ({"value": "NaCl-suf", "encoding": "utf8", "position": "suffix"}, b"NaCl-suf", "suffix"),
         "prefix-hex": ({"value": "dead", "encoding": "hex", "position": "prefix"}, bytes.fromhex("dead"), "prefix")}
for kname, (key, keyraw) in KEYS.items():
    for sname, (salt, saltraw, pos) in SALTS.items():
        data = PW.encode() + saltraw if pos == "suffix" else saltraw + PW.encode()
        mac = run(["openssl", "mac", *OSSL, "-digest", "whirlpool", "-macopt", "hexkey:" + keyraw.hex(),
                   "-binary", "HMAC"], data)
        enc = "hex" if kname in ("utf8", "hex") else "base64"
        spec = {"algorithm": "hmac", "hash": {"value": mac.hex() if enc == "hex" else base64.b64encode(mac).decode(),
                                              "encoding": enc, "digest": "whirlpool", "key": key}}
        if salt:
            spec["salt"] = salt
        add("hmac/whirlpool/key-%s/salt-%s" % (kname, sname), spec, PW)

with open("internal/passhash/testdata/vectors-kdf.json", "w") as f:
    json.dump(VECTORS, f, indent=1)
    f.write("\n")
