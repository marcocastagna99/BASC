import shutil



'''how i calculate the target_offset
    entry point VA= 0x0000000000402000
    offset= 0x0000000000002000
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
    modified_file = "../files/toppler64__infinity_lives"  # The new modified file
    copy_executable(original_file, modified_file)
    
    # Step 2: Define the offset and the bytes to insert
    target_offset =  0x14005  # Offset of the SUB instruction
    nop_bytes = b'\x83\xe8\x00' # subtraction of 0 instead of 1
    
    # Step 3: Modify the copied executable
    modify_executable(modified_file, target_offset, nop_bytes)
    print(f"Modified file saved as {modified_file}")



def freeze_time(original_file):
    # Step 1: Copy the original executable
    modified_file = "../files/toppler64__freeze_time"  # The new modified file
    copy_executable(original_file, modified_file)
    
    # Step 2: Define the offset and the bytes to insert
    target_offset =  0x63fe  # Offset of the LEA instruction
    new_bytes= b'\x8d\x50\x00' # 00 instead of ff
    # Step 3: Modify the copied executable
    modify_executable(modified_file, target_offset, new_bytes)
    print(f"Modified file saved as {modified_file}")

def more_lives(original_file):
    # Step 1: Copy the original executable
    modified_file = "../files/toppler64__more_lives"  # The new modified file
    copy_executable(original_file, modified_file)
    
    # Step 2: Define the offset and the bytes to insert
    target_offset =  0x4288  # Offset of the cmp instruction
    new_bytes= b'\x83\xF8\xff' # 0x64 = 100 in decimal instead of 0x3 
    
    # Step 3: Modify the copied executable
    modify_executable(modified_file, target_offset, new_bytes)

    target_offset= 0x4291 # Offset of the mov instruction
    new_bytes = b'\xC7\x40\x40\xFF\x00\x00\x00'  # 0xff = 255 in decimal instead of 0x3
    modify_executable(modified_file, target_offset, new_bytes)
    print(f"Modified file saved as {modified_file}")




def no_collisions(original_file):
    # Step 1: Copy the original executable
    modified_file = "../files/toppler64__no_collisions"  # The new modified file
    copy_executable(original_file, modified_file)
    
    # Step 2: Define the offset and the bytes to insert
    target_offset =  0x14a4e # Offset of the jg instruction
    new_bytes= b'\xc7\x45\xfc\x04\x00\x00\x00' # 0x4 = 4 in decimal instead of 0x0
    
    # Step 3: Modify the copied executable
    modify_executable(modified_file, target_offset, new_bytes)
    print(f"Modified file saved as {modified_file}")
    



# Main function
def main():
    original_file = "../files/toppler64"  # The original file to modify
    while True:
        # Display the available hacks
        print("1. Infinite lives")
        print("2. freeze time")
        print("3. more lives")
        print("4. No collisions")
        print("5. Exit")   
        #switch case
        choice = input("Enter your choice: ")
        if choice == "1":
            infinite_lives(original_file)
        elif choice == "2":
            freeze_time(original_file)
        elif choice == "3":
            more_lives(original_file)
        elif choice == "4":
            no_collisions(original_file)
        elif choice == "5":
            print("Exiting...")
            break
        else:
            print("Invalid choice. Please enter a valid option.")


# Run the program
if __name__ == "__main__":
    main()
