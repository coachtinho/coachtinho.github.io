---
title: "HSCTF - HS Bank"
date: 2022-05-25
tags: [hsctf, crypto, brute_force]
draft: false
---

{{< lead >}}
This challenge was part of a CTF event hosted by [HackerSchool](https://hackerschool.io).
{{< /lead >}}

## Challenge statement

For this challenge, a single python script was provided:

```python
import string
import hashlib
import random

def banc_pass(password2hash):
	hashresult = hashlib.md5(password2hash).digest()
	sha1 = hashlib.sha1(hashresult)
	sha256 = hashlib.sha256(sha1.digest())
	for i in range(0, 10):
		sha1 = hashlib.sha1(sha256.digest())
		sha256 = hashlib.sha256(sha1.digest())
	output = sha256.hexdigest()
	return output

def impossible_pass():
	a = random.choice(string.ascii_letters) 
	b = random.choice(string.ascii_letters)
	c = random.choice(string.ascii_letters)
	secret = banc_pass((a+b+c).encode())

	return secret

def banc_login():
	secret_of_the_day = ""
	for i in range(10):
		secret_of_the_day += impossible_pass()
	print("Bem vindo ao HSBanco!\n")
	print("Vamos mostrar de seguida o segredo do dia!\n")
	print("Segredo do dia é {}\n".format(secret_of_the_day))

	# On that day the secret was: da7769f9bb80ce4ed1e4977403d9aff67f5a5e0e50686aeff5fa493e850a1d2a6c9e02a05a59c51c624fb77684e40086cb07438eba32c42074df2a718be41ee9fc338739267b25b92765ebdee1a767c8855e32d2a2e0cd1216ba1ddeae6933a7a2e692e1a6413f718c8a2078f8ce0872c76e2a287d240af4b81b3ce1c193a6316a5a8fe23dcc00ce5b86bca445d98cb08615b16a3766cc12004a5a2bcbc2d3e04cefbd24bf6394c778a1f88b5b50283b972177388bdfa645f667762472704c6477e32e728d9935a26eb4e621fd4f83e93a9bd32ec812a104c4e0ed42c49ab8c5d3159d056764b89c4cd1d310026a083cb7cb0b9af91728235c59ae4dde83e956184224d98c9d59fef5d1e61c36498958a16a4529efc162effd15cacf5359466093337c2a06ffeb72c4f54bf992651ca52591169aee8301e6dd30e9f2d68f19ad
if __name__ == '__main__':
	banc_login()
```

This python script showcases the generation of a secret originated from a **password** as well as a generated secret.
The objective of the challenge is to figure out what **password** generated the provided secret and enclose it within *HS{}* to get the flag.

## Solution

Analysing the code, the first aspect that comes to mind is that the secret is created by concatenating 10 different results from the `impossible_pass` function.
This function simply picks 3 random ascii letters and hashes them multiple times with 3 different algorithms (MD5, SHA1, SHA256).
As a result, the secret can be split into 10 different SHA256 hashes.
Since each of these hashes is calculated from only 3 random ascii letters, the search space is small enough that each one of them can be brute forced individually.

## Cracking the password

The **password** can be obtained through the following script, which took only 8 seconds to run on my machine:

```python
import string
import hashlib

# Split secret into 10 different hashes
secret = "da7769f9bb80ce4ed1e4977403d9aff67f5a5e0e50686aeff5fa493e850a1d2a6c9e02a05a59c51c624fb77684e40086cb07438eba32c42074df2a718be41ee9fc338739267b25b92765ebdee1a767c8855e32d2a2e0cd1216ba1ddeae6933a7a2e692e1a6413f718c8a2078f8ce0872c76e2a287d240af4b81b3ce1c193a6316a5a8fe23dcc00ce5b86bca445d98cb08615b16a3766cc12004a5a2bcbc2d3e04cefbd24bf6394c778a1f88b5b50283b972177388bdfa645f667762472704c6477e32e728d9935a26eb4e621fd4f83e93a9bd32ec812a104c4e0ed42c49ab8c5d3159d056764b89c4cd1d310026a083cb7cb0b9af91728235c59ae4dde83e956184224d98c9d59fef5d1e61c36498958a16a4529efc162effd15cacf5359466093337c2a06ffeb72c4f54bf992651ca52591169aee8301e6dd30e9f2d68f19ad"
hashes = [secret[i:i+64] for i in range(0, len(secret), 64)]

def banc_pass(password2hash):
	hashresult = hashlib.md5(password2hash).digest()
	sha1 = hashlib.sha1(hashresult)
	sha256 = hashlib.sha256(sha1.digest())
	for i in range(0, 10):
		sha1 = hashlib.sha1(sha256.digest())
		sha256 = hashlib.sha256(sha1.digest())
	output = sha256.hexdigest()
	return output


def get_secret(target):
    for a in string.ascii_letters:
        for b in string.ascii_letters:
            for c in string.ascii_letters:
                if banc_pass((a+b+c).encode()) == target:
                    return a+b+c
    return ""


if __name__ == '__main__':
    password = ""
    for target in hashes:
        # Brute force each hash individually
        password += get_secret(target)
    print("HS{" + password + "}")
```
