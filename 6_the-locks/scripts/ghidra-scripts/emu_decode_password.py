from unicorn import *
from unicorn.x86_const import *

emu = Uc(UC_ARCH_X86, UC_MODE_64)

# Constants
CODE_ADDR = 0x001010B0 # Address of the .text
CODE_SIZE = 0x11823    # Size of the .text
STACK_ADDR = 0x200000
STACK_SIZE = 1024 * 1024

DATA_ADDR = 0x117040 # Address of the .data
DATA_SIZE = 0x6e8 # Size of the .data

aligned_data_addr = DATA_ADDR & ~0xFFF   # Align the address to the page size
dat_size_aligned = (DATA_SIZE + 0xFFF) & ~0xFFF  # Align the size to the page size
offset = DATA_ADDR - aligned_data_addr

print(f"DATA_ADDR: {hex(DATA_ADDR)}")
print(f"Aligned address: {hex(aligned_data_addr)}")
print(f"dat_size_aligned: {hex(dat_size_aligned)}")

#the data to be emulated
all_bytes_data = bytes(b & 0xff for b in getBytes(toAddr(DATA_ADDR), DATA_SIZE))

# Map the memory for the data
try:
    emu.mem_map(aligned_data_addr, dat_size_aligned, UC_PROT_READ | UC_PROT_WRITE)
    emu.mem_write(DATA_ADDR, all_bytes_data) 
    print(f"Memory mapped and data written successfully.")
except UcError as e:
    print(f"Error mapping memory: {e}")




# emu.mem_map(0x00101000, 0x20000, UC_PROT_READ | UC_PROT_WRITE | UC_PROT_EXEC)
start_addr = CODE_ADDR & ~0xFFF
# Calculate end address (aligned upwards)
end_addr = (CODE_ADDR + CODE_SIZE + 0xFFF) & ~0xFFF
# Total size of memory to map
PG_CODE_SIZE = end_addr - start_addr

print(f"Start address: {hex(start_addr)}, End address: {hex(end_addr)}, Mapped size: {hex(PG_CODE_SIZE)}")

# Map the memory from start_addr to end_addr
emu.mem_map(start_addr, PG_CODE_SIZE, UC_PROT_READ | UC_PROT_WRITE | UC_PROT_EXEC)

# code data to be emulated
all_bytes = bytes(b & 0xff for b in getBytes(toAddr(CODE_ADDR), CODE_SIZE))
emu.mem_write(CODE_ADDR, all_bytes)  # Write the code to memory

# Map the stack
emu.mem_map(STACK_ADDR, STACK_SIZE, UC_PROT_READ | UC_PROT_WRITE)
emu.reg_write(UC_X86_REG_RSP, STACK_ADDR + STACK_SIZE - 8)  # Set the stack pointer

# Hook function for code
def hook_code(emu, address, size, user_data):
        print(f'Instruction at 0x{address:x}, instruction size = {size}')

# Add hooks
emu.hook_add(UC_HOOK_CODE, hook_code)

# Start emulation
emu.emu_start(0x0010177d, 0x00101791)

# Decode in hexadecimal
emu_dec_data1 = emu.mem_read(0x117700, 0x1a)
print(f"Decoded data: {emu_dec_data1.hex()}")

emu_dec_data1 = emu.mem_read(0x117700, 0x1a).decode('latin1')
print("password:", emu_dec_data1)
