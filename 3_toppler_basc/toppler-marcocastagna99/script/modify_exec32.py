import shutil



'''how i calculate the target_offset
    entry point VA= 0x0804a000
    offset= 0x002000
    my_instruction_VA= virtual address of the instruction I want to modify

    target_offset= (my_instruction_VA - entry point_VA) + offset 
    '''




# Function to copy the executable file
def copy_executable(original_file, modified_file):
    shutil.copy(original_file, modified_file)
    #print(f"File {original_file} copied as {modified_file}")



# Function to modify the byte at the specified offset
def modify_executable(file_path, target_offset, new_bytes):
    # Open the executable in read-write binary mode
    with open(file_path, "r+b") as f:
        content = f.read()

        # Check if the offset is valid
        if target_offset >= len(content):
            print(f"Error: The offset {target_offset} is outside the file bounds.")
            return

        # Modify the byte at the specified offset with the new bytes
        content = content[:target_offset] + new_bytes + content[target_offset + len(new_bytes):]

        # Write the modified content back to the file
        with open(file_path, "wb") as f_out:
            f_out.write(content)


def infinite_lives(original_file):
    # Step 1: Copy the original executable
    modified_file = "../files/toppler32__infinity_lives"  # The new modified file
    copy_executable(original_file, modified_file)
    
    # Step 2: Define the offset and the bytes to insert
    target_offset =  0xe417  # Offset of the SUB instruction
    nop_bytes = b'\x90\x90\x90'  # NOP instruction (0x90)
    
    # Step 3: Modify the copied executable
    modify_executable(modified_file, target_offset, nop_bytes)
    print(f"Modified file saved as {modified_file}")



def more_lives(original_file):
    # Step 1: Copy the original executable
    modified_file = "../files/toppler32__more_lives"  # The new modified file
    copy_executable(original_file, modified_file)
    
    # Step 2: Define the offset and the bytes to insert
    target_offset =  0x7c9f  # Offset of the cmp instruction
    new_bytes= b'\x83\xF8\x64' # 0x64 = 100 in decimal instead of 0x3 
    
    # Step 3: Modify the copied executable
    modify_executable(modified_file, target_offset, new_bytes)

    target_offset= 0xbca4 # Offset of the mov instruction
    new_bytes= b'\xc7\x05\xf8\x64\x06\x08\x64\x00\x00\x00' # 0x64 = 100 in decimal
    modify_executable(modified_file, target_offset, new_bytes)
    print(f"Modified file saved as {modified_file}")


def freeze_time(original_file):
    # Step 1: Copy the original executable
    modified_file = "../files/toppler32__freeze_time"  # The new modified file
    copy_executable(original_file, modified_file)
    
    # Step 2: Define the offset and the bytes to insert
    target_offset =  0x44f1  # Offset of the cmp instruction
    new_bytes= b'\x83\xe8\x00' # subtraction of 0 instead of 1
    
    # Step 3: Modify the copied executable
    modify_executable(modified_file, target_offset, new_bytes)
    print(f"Modified file saved as {modified_file}")



def no_robot(original_file):
    # Step 1: Copy the original executable
    modified_file = "../files/toppler32__no_robot"  # The new modified file
    copy_executable(original_file, modified_file)
    
    # Step 2: Define the offset and the bytes to insert
    target_offset =  0xea6c # Offset of the jg instruction
    new_bytes= b'\xEB\x46' # incoditional jump: JMP instead of JG
    
    # Step 3: Modify the copied executable
    modify_executable(modified_file, target_offset, new_bytes)
    print(f"Modified file saved as {modified_file}")



#0f b7 05 70 0b 02 00  movzx eax, word [0x20b70]
#b8 ff ff ff ff 90 90  mov eax, 0xffffffff;nop;nop
def more_time(original_file):
    # Step 1: Copy the original executable
    modified_file = "../files/toppler32__more_time"  # The new modified file
    copy_executable(original_file, modified_file)
    
    # Step 2: Define the offset and the bytes to insert
    target_offset =  0x70eb  # Offset of the movzx instruction
    new_bytes= b'\xb8\xff\xff\xff\xff\x90\x90' # mov eax, 0xffffffff
    
    # Step 3: Modify the copied executable
    modify_executable(modified_file, target_offset, new_bytes)
    print(f"Modified file saved as {modified_file}")
    




# Main function
def main():
    original_file = "../files/toppler32"  # The original file to modify
    while True:
        # Display the available hacks
        print("1. Infinite lives")
        print("2. more lives")
        print("3. freeze time")
        print("4. No robot")
        print("5. More time")
        print("6. Exit")
        #switch case
        choice = input("Enter your choice: ")
        if choice == "1":
            infinite_lives(original_file)
        elif choice == "2":
            more_lives(original_file)
        elif choice == "3":
            freeze_time(original_file)
        elif choice == "4":
            no_robot(original_file)
        elif choice == "5":
            more_time(original_file)
        elif choice == "6":
            print("Exiting...")
            break
        else:
            print("Invalid choice. Please enter a valid option.")
         


# Run the program
if __name__ == "__main__":
    main()
