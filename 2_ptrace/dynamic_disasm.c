#include <stdio.h>                   // Standard input/output definitions
#include <stdlib.h>                  // Standard library definitions
#include <sys/ptrace.h>             // Header for ptrace system call
#include <sys/types.h>              // Header for data types used in system calls
#include <sys/wait.h>               // Header for waiting for process state changes
#include <sys/user.h>               // Header for user register structures
#include <unistd.h>                 // Header for POSIX operating system API (fork, exec, etc.)
#include <capstone/capstone.h>      // Capstone disassembly framework header
#include <errno.h>                   // Error number definitions
#include <string.h>                  // String manipulation definitions
#include <signal.h>                  // Signal handling definitions

#define CODE_BUFFER_SIZE 16         // Define the buffer size for reading a single instruction

int main(int argc, char *argv[]) {
    // Check if the program name and at least one argument are provided
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <program> [args...]\n", argv[0]);
        return 1;  // Exit with error code
    }

    pid_t child_pid = fork();  // Create a new process by duplicating the current process
    if (child_pid == -1) {     // Check if fork failed
        perror("fork");         // Print error message
        return 1;              // Exit with error code
    }

    if (child_pid == 0) {      // Child process
        // Allow the parent to trace this process
        ptrace(PTRACE_TRACEME, 0, NULL, NULL);
        // Replace the child process image with the specified program
        execvp(argv[1], &argv[1]);
        perror("execvp");       // Print error if exec fails
        return 1;              // Exit with error code
    } else {
        // Parent process
        int status;                     // Status of the child process
        struct user_regs_struct regs;   // Structure to hold the registers of the child process
        csh handle;                     // Handle for Capstone disassembly engine
        cs_insn *insn;                  // Pointer to the disassembled instructions
        size_t count;                   // Count of disassembled instructions
        long instruction_count = 0;     // Count the number of instructions executed by the child process

        // Initialize Capstone disassembly engine for 64-bit x86 architecture
        if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK) {
            fprintf(stderr, "Failed to initialize Capstone\n");
            return 1;  // Exit with error code
        }

        while (1) {
            // Wait for the child process to change state
            waitpid(child_pid, &status, 0);
            if (WIFEXITED(status)) {         // Check if the child process has exited
                printf("Child exited;\n");    // Print message indicating child exit
                break;                       // Exit the loop
            }

            if (WIFSTOPPED(status) && WSTOPSIG(status) == SIGTRAP) { // Check if stopped by SIGTRAP
                // Get the registers of the child process
                ptrace(PTRACE_GETREGS, child_pid, NULL, &regs);

                // Read the instruction bytes from the child's memory
                unsigned char code[CODE_BUFFER_SIZE]; // Buffer to hold the instruction bytes
                for (int i = 0; i < CODE_BUFFER_SIZE; i++) {
                    code[i] = ptrace(PTRACE_PEEKTEXT, child_pid, regs.rip + i, NULL); // Read memory at instruction pointer
                }

                // Disassemble the instruction using Capstone
                count = cs_disasm(handle, code, CODE_BUFFER_SIZE, regs.rip, 1, &insn);
                if (count > 0) { // Check if disassembly was successful
                    instruction_count++; // Increment the instruction count
                    // Print the address, mnemonic, and operand string of the instruction
                    printf("0x%" PRIx64 ": %s %s\n", insn[0].address, insn[0].mnemonic, insn[0].op_str);
                    cs_free(insn, count); // Free the memory allocated for instructions
                } else {
                    // Print error if disassembly fails
                    fprintf(stderr, "ERROR: Failed to disassemble at 0x%llx\n", regs.rip);
                }
            }
            
            // Step to the next instruction 
            if (ptrace(PTRACE_SINGLESTEP, child_pid, NULL, NULL) == -1) {
                perror("ptrace"); // Print error if ptrace fails
                break;            // Exit the loop on error
            }
        }
        printf("n_instructions= %ld\n", instruction_count);
        cs_close(&handle); // Close the Capstone disassembly engine
    }

    return 0; // Exit the program successfully
}
