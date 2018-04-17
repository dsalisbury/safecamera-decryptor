# safecamera-decryptor

## What?

This makes it easy to decrypt en masse the encrypted images/files from
Safecamera in a CLI-/automation-friendly way.


## Why?

I'm trying to go as paperless as possible and I have a huge backlog of paper to
scan using a scanner which is quite slow; taking photos on my phone is fast but
I want to ensure that the resulting images are not only stored encrypted but
also decryptable on my terms so that I'm not locked into any solution.
Safecamera is an app which appears to satisfy these requirements (provided a
small amount of work to produce this decryptor).

There is a [GUI app](https://www.safecamera.org/desktop/) available for opening
and decrypting the images/files, but I need something which I can run against
hundreds of files without needing any manual steps.


## How are files encrypted?

Note: this is a summary; see the [source code of the desktop app](
https://bitbucket.org/alexamiryan/safecameradesktop/commits/branch/master) for
more info.

At a high level, a symmetric encryption/decryption key is derived from a
master password and a salt, and is used to encrypt both the name and contents
of the file. The encrypted filename is dumped alongside the IV and salt in the
name of the output file; it is a similar story for the encrypted content of the
file, which is dumped after a six-byte header, the IV, and the salt.


### Salt and initialization vector

The salt is 32 bytes long and the initialization vector is 16 bytes long.


### The encryption/decryption key

To obtain the encryption/decryption key:

1. the master password is hashed using SHA-512
2. use the salt and master password hash to derive the key (using 2048
   iterations of SHA-256 and following the rules of PKCS12)

The derivation is implemented in fareliner/jasypt4py, which produces keys in
the same way as the [PBEParametersGenerator class](
http://bouncycastle.org/docs/docs1.5on/org/bouncycastle/crypto/
PBEParametersGenerator.html) in the Bouncy Castle Java APIs.


### Encrypted formats

#### Filename

The encrypted file has the following form (in ABNF-ish form):

```
prefix = "zzSC"
hex-iv = hexdump(iv)
hex-salt = hexdump(salt)
hex-name = hexdump(encrypted_name)
output file name = prefix "-" counter "_" hex-iv hex-salt hex-name
```


#### Content

The encrypted file has the following ABNF-ish form:

```
header = "SCAES"
version = 1
output file content = header version iv salt encrypted_content
```
