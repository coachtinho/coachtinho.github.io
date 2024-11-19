---
title: "Sinfo CTF - PySides Easy"
date: 2023-04-30
tags: [sinfoctf, crypto]
draft: false
---

{{< lead >}}
This challenge was part of a CTF event hosted by [SINFO 30](https://sinfo.org/).
{{< /lead >}}

## Challenge statement

This challenge provided a single Python file with a password verifier:

```python
#!/usr/bin/env python3

import os
password = os.environ['FLAG']

print("""
  Welcome to the server!
  Today we will learn about side channels.
  We will be using a simple script to demosntrate how side channels work.
  All you have to do for this channel is find out the password of the user.
""")

# print("The password is: " + password)
print("Please enter the password: ", end="")

r = input()
for i in range(len(password)):
  if r[i] != password[i]:
    print(f"Wrong password!")
    break
  print("OK!")
else:
  print("Correct password! The flag is: " + password)
```

## Objective

The goal of this challenge is to guess the password (the flag) using a side channel attack.
The verifier checks the user provided guess one character at a time and provides feedback for each correct character.
This means that it's possible to brute force each character of the password, one at a time.

## Solution

The challenge can be solved by iterating over each position of the password, starting at 0, and trying every possible character until the number of correct characters increases.
This can be achieved with the following script:

```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template chall_easy.py
from pwn import *

# Set up pwntools for the correct architecture
context.update(arch='i386')
exe = 'chall_easy.py'

# Many built-in settings can be controlled on the command-line and show up
# in "args".  For example, to dump all data sent/received, and disable ASLR
# for all created processes...
# ./exploit.py DEBUG NOASLR


def start(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    if args.GDB:
        return gdb.debug([exe] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe] + argv, *a, **kw)

# Specify your GDB script here for debugging
# GDB will be launched if the exploit is run via e.g.
# ./exploit.py GDB
gdbscript = '''
continue
'''.format(**locals())

#===========================================================
#                    EXPLOIT GOES HERE
#===========================================================
from string import printable

guess = list(b"A" * 64)
flag = ""

i = 0
while i < len(guess):
    for p in printable:
        guess[i] = ord(p)

        # Change log level so stdout isn't flooded with messages
        temp = context.log_level
        context.log_level = 'critical'
        io = start()
        context.log_level = temp

        io.recvuntil(b"password: ")
        io.sendline(bytes(guess))
        res = io.recv()

        # Change log level so stdout isn't flooded with messages
        temp = context.log_level
        context.log_level = 'critical'
        io.close()
        context.log_level = temp

        if b"Correct" in res:
            flag = bytes(guess[:i+1]).decode()
            break

        # Move cursor to next unknown byte
        if res.count(b"OK") > i:
            log.info(bytes(guess).decode())
            i = res.count(b"OK")
            break

    if flag != "":
        log.success(flag)
        break


if flag == "":
    log.failure("Flag not found")
```
