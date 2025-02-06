from pwn import *
import re

EXE_FILENAME='../binaries/marcocastagna99-the_lock-level_1'
exe = context.binary = ELF(EXE_FILENAME)
argv = [EXE_FILENAME]
envp = {}
gdbscript = '''
set startup-with-shell off
b strcmp

'''

def start():
    if args.GDB:
        return gdb.debug(args=argv, env=envp, gdbscript=gdbscript)
    return process(argv=argv, env=envp)
    
#ghidra super password address 0002a6f8
OFFSET_DECODE_PASSWORD= 4711  #11267 ghidra
#OFFSET_CHECK_PASSWORD= 4875   #1130b ghidra
#OFFSET_OVERWRITE= 4770        #112a2 ghidra
PASSWORD_OFFSET = 108280



io = start()
output= io.recvuntil(b"super-secret-password")
output+= io.recv(2024)
print(output)

def extract_leaked_addresses(output):
    # Regex to capture hexadecimal addresses (preceded by "0x")
    pattern = re.compile(r"0x[0-9a-fA-F]+")
    
    leaked_address = []
    
    # Iterate over each line and search for hexadecimal addresses
    for line in output.splitlines():
        # Decode the line and remove ANSI characters
        decoded_line = line.decode('utf-8', 'ignore').replace("\x1b[0m", "").replace("\x1b[0;35m", "").strip()
        
        # Find all addresses in the line
        matches = pattern.findall(decoded_line)
        leaked_address.extend(matches)
    
    return leaked_address



leaked_addresses = extract_leaked_addresses(output)

print(leaked_addresses)

#BASE OFFSET
base_offset = int(leaked_addresses[0], 16) - OFFSET_DECODE_PASSWORD
print(f"Base offset: 0x{base_offset:x}")

#decode_function_address = base_offset + OFFSET_DECODE_PASSWORD  #int(leaked_address[0])
#check_function_address = base_offset + OFFSET_CHECK_PASSWORD    #int(leaked_address[1])
#overwrite_address = base_offset + OFFSET_OVERWRITE              #int(leaked_address[2])
password_address = int(leaked_addresses[3], 16)

print(f"Password address: 0x{password_address:x}")
#password_address_founded = base_offset + PASSWORD_OFFSET
#print(f"Password address founded: 0x{password_address_founded:x}")

password_bytes = exe.read(PASSWORD_OFFSET, 12) #read 12 bytes from password address
print(f"Password bytes: {password_bytes}")  #show bytes
decoded_password = bytes([(b + 0xD1) & 0xFF for b in password_bytes]) # apply the decode function
print(f"Decoded password (ASCII): {decoded_password.decode('utf-8')}")




io.sendline(decoded_password)
output= io.recv(200)
print(f"Output:\n{output.decode('utf-8', errors='ignore')}")

io.close()      




