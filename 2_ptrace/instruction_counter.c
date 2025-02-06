#include <stdio.h>                  
#include <stdlib.h>                 
#include <sys/ptrace.h>             // Header for the ptrace system call, used for process tracing
#include <sys/types.h>              // Header for data types used in system calls
#include <sys/wait.h>               // Header for waiting for process state changes
#include <sys/user.h>               // Header for user register structures
#include <unistd.h>                 // Header for POSIX operating system API (fork, exec, etc.)
#include <signal.h>                 // Header for signal constants (e.g., SIGTRAP)

int main(int argc, char *argv[]) {
    // Check if the program name and at least one argument (the program to trace) are provided
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <program> [args...]\n", argv[0]);
        return 1;  // Exit with an error code
    }

    pid_t child = fork();  // Create a new process by duplicating the current process
    if (child == -1) {     // Check if fork failed
        perror("fork");     // Print error message for fork failure
        return 1;          // Exit with an error code
    }

    if (child == 0) {      // Child process
        // Initiate tracing for this child process
        ptrace(PTRACE_TRACEME, 0, NULL, NULL);
        // Replace the child process image with the specified program and its arguments
        execvp(argv[1], &argv[1]);
        perror("execvp");   // Print error message if exec fails
        return 1;          // Exit with an error code
    } else {
        // Parent process
        int status;                       // Status of the child process
        long instruction_count = 0;       // Count the number of instructions executed by the child process

        // Wait for the child process to stop after executing the program
        waitpid(child, &status, 0);

        // Trace each instruction while the child process is stopped
        while (WIFSTOPPED(status)) {       // Check if the child process is currently stopped
            if (WSTOPSIG(status) == SIGTRAP) {  // Check if the signal that caused the stop is SIGTRAP, indicating a single-step
                instruction_count++;            // Increment the instruction count
            }

            // Step through the child process's execution one instruction at a time
            ptrace(PTRACE_SINGLESTEP, child, NULL, NULL);
            // Wait for the child process to stop again (after stepping)
            waitpid(child, &status, 0);
        }

        printf("Child exited; n_instructions=%ld\n", instruction_count);
    }

    return 0;
}
