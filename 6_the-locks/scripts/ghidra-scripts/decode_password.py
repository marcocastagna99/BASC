def read_c_string(addr):
    result = bytearray()
    while True:
        byte = getByte(addr) & 0xff
        if byte == 0:
            break
        if monitor().isCancelled():
            return None
        result.append(byte)
        addr = addr.next()
    return result





def modify_bytes_and_read_c_string(addr, size):
    modified_result = bytearray()
    
    for _ in range(size):
        if monitor().isCancelled():
            return None
        byte = getByte(addr) & 0xff
        if byte == 0:
            break
        
        # Add 0xd1 to the byte and ensure the result is always a byte (modulo 0xFF)
        modified_byte = (byte + 0xd1) & 0xff
        
        # Append the modified byte to the result
        modified_result.append(modified_byte)
        
        addr = addr.next()

    return modified_result

# Starting address and the size of bytes (12)
addr = toAddr(0x0002a6f8)
size = 12

# Read and modify the bytes
modified_bytes = modify_bytes_and_read_c_string(addr, size)



# Print the modified bytes and their string representation
original_bytes= read_c_string(addr)
print(f"original bytes: {original_bytes}")
print(f"Resulting string: {modified_bytes.decode('utf-8')}")
