from pwn import *
import re

EXE_FILENAME='../binaries/marcocastagna99-the_lock-level_2'
exe = context.binary = ELF(EXE_FILENAME)
argv = [EXE_FILENAME]
envp = {}
gdbscript = '''
set startup-with-shell off

'''

def start():
    if args.GDB:
        return gdb.debug(args=argv, env=envp, gdbscript=gdbscript)
    return process(argv=argv, env=envp)
    
PASSWORD_OFFSET = 96000



io = start()
output= io.recvuntil(b"super-secret-password")
output+= io.recv(2024)
password_bytes = exe.read(PASSWORD_OFFSET, 0X1a) #read 26 bytes from password address
password_bytes = list(password_bytes)


def manipulate_buffer(buffer):
    if len(buffer) < 26:  
        raise ValueError("Il buffer deve contenere almeno 26 elementi.")

    buffer[0x15] = (buffer[0x15] + (-0x31)) & 0xFF
    buffer[8] = (buffer[8] + ord(']')) & 0xFF
    buffer[0x12] = buffer[0x12] ^ 0x7E
    buffer[0x0B] = (buffer[0x0B] + ord(':')) & 0xFF
    buffer[0x14] = buffer[0x14] ^ 0x7D
    buffer[7] = (buffer[7] + ord('/')) & 0xFF
    buffer[0x11] = buffer[0x11] ^ 0x44
    buffer[0x18] = (buffer[0x18] + ord('6')) & 0xFF
    buffer[0x0E] = (buffer[0x0E] + 0x14) & 0xFF
    buffer[1] = (buffer[1] + (-4)) & 0xFF
    buffer[0x17] = (buffer[0x17] + (-0x11)) & 0xFF
    buffer[0x13] = (buffer[0x13] + ord('O')) & 0xFF
    buffer[0x10] = (buffer[0x10] + ord('\\')) & 0xFF
    buffer[0x16] = buffer[0x16] ^ 0x3B
    buffer[4] = (buffer[4] + (-0x29)) & 0xFF
    buffer[3] = (buffer[3] + (-0x12)) & 0xFF
    buffer[0x0D] = (buffer[0x0D] + ord('L')) & 0xFF
    buffer[0] = (buffer[0] + (-0x75)) & 0xFF
    buffer[5] = (buffer[5] + (-0x5A)) & 0xFF
    buffer[0x0C] = (buffer[0x0C] + ord('$')) & 0xFF
    buffer[0x0F] = (buffer[0x0F] + ord('-')) & 0xFF
    buffer[2] = buffer[2] ^ 0x4E
    buffer[0x19] = buffer[0x19] ^ 0x2D
    buffer[6] = (buffer[6] + ord('/')) & 0xFF
    buffer[9] = (buffer[9] + 0x1F) & 0xFF
    buffer[10] = (buffer[10] + (-0x49)) & 0xFF

    return buffer
decoded_password = manipulate_buffer(password_bytes)
decoded_password_str = ''.join(chr(byte) for byte in decoded_password)
print(f"Decoded password (ASCII):  {decoded_password_str}")

io.sendline(decoded_password_str.encode('utf-8'))
output= io.recv(200)
print(f"Output:\n{output.decode('utf-8', errors='ignore')}")

io.close()      




