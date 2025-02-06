
# Second Assignment

## Program 1: Instruction Counter (`instruction_counter.c`)

### Key Code Sections:

- **Creating and Tracing the Process:**
  ```c
  pid_t child = fork();  // Create a child process
  if (child == 0) {
      ptrace(PTRACE_TRACEME, 0, NULL, NULL);  // Let the parent trace this process
      execvp(argv[1], &argv[1]);  // Run the specified program
      perror("execvp");   // Show an error if exec fails
      return 1;          // Exit with an error code
  }
  ```
  - **Explanation:**
    - The program starts by creating a child process with `fork()`.
    - If successful, the child process (where `child == 0`) allows the parent to trace it by using `ptrace(PTRACE_TRACEME)`.
    - The child then runs the specified program with `execvp()`. If this fails, it prints an error message.

- **Counting Instructions:**
  ```c
  while (WIFSTOPPED(status)) {
      if (WSTOPSIG(status) == SIGTRAP) {  // Check if the stop signal is SIGTRAP
          instruction_count++;  // Increase instruction count
      }

      // Move through the child's execution one instruction at a time
      ptrace(PTRACE_SINGLESTEP, child, NULL, NULL);  // Move to the next instruction
      waitpid(child, &status, 0);  // Wait for the child to stop again
  }
  ```
  - **Explanation:**
    - The parent enters a loop that continues as long as the child is stopped. It checks if the child is stopped using `WIFSTOPPED(status)`.
    - Inside the loop, it checks for the `SIGTRAP` signal, which means the program stopped for a special reason (like stepping through code).
    - If `SIGTRAP` is detected, it increases the `instruction_count` to track how many instructions were executed.
    - The program then calls `ptrace(PTRACE_SINGLESTEP)` to execute the next instruction in the child process.
    - Finally, `waitpid(child, &status, 0)` waits for the child to stop again after executing the next instruction.

## Program 2: Dynamic Disassembler (`dynamic_disasm.c`)

### Key Code Sections:

- **Setup and Tracing:**
  ```c
  pid_t child_pid = fork();  // Create a child process
  if (child_pid == 0) {
      ptrace(PTRACE_TRACEME, 0, NULL, NULL);  // Allow tracing
      execvp(argv[1], &argv[1]);  // Run the specified program
      perror("execvp");       // Show an error if exec fails
      return 1;              // Exit with an error code
  }
  ```
  - **Explanation:**
    - Like the first program, this section creates a child process and enables tracing using `ptrace(PTRACE_TRACEME)`.
    - The child runs the specified program, and if `execvp()` fails, it prints an error message.

- **Reading Instructions and Disassembling:**
  ```c
  while (1) {
      waitpid(child_pid, &status, 0);
      if (WIFEXITED(status)) {         // Check if the child has exited
          printf("Child exited;\n");    // Print a message indicating exit
          break;                       // Exit the loop
      }

      if (WIFSTOPPED(status) && WSTOPSIG(status) == SIGTRAP) { // Check if stopped by SIGTRAP
          // Get the child's registers
          ptrace(PTRACE_GETREGS, child_pid, NULL, &regs);

          // Read the instruction bytes from the child's memory
          unsigned char code[CODE_BUFFER_SIZE]; // Buffer to hold instruction bytes
          for (int i = 0; i < CODE_BUFFER_SIZE; i++) {
              code[i] = ptrace(PTRACE_PEEKTEXT, child_pid, regs.rip + i, NULL); // Read memory at instruction pointer
          }

          // Disassemble the instruction using Capstone
          count = cs_disasm(handle, code, CODE_BUFFER_SIZE, regs.rip, 1, &insn);
          if (count > 0) { // Check if disassembly was successful
              instruction_count++; // Increase the instruction count
              // Print the address and details of the instruction
              printf("0x%" PRIx64 ": %s %s\n", insn[0].address, insn[0].mnemonic, insn[0].op_str);
              cs_free(insn, count); // Free memory allocated for instructions
          } else {
              // Print error if disassembly fails
              fprintf(stderr, "ERROR: Failed to disassemble at 0x%llx\n", regs.rip);
          }
      }

      // Move to the next instruction 
      if (ptrace(PTRACE_SINGLESTEP, child_pid, NULL, NULL) == -1) {
          perror("ptrace"); // Show error if ptrace fails
          break;            // Exit the loop on error
      }
  }
  printf("n_instructions= %ld\n", instruction_count);
  ```
  - **Explanation:**
    - This loop keeps checking the child process. It waits for the child to change state with `waitpid()`.
    - If the child has exited (checked with `WIFEXITED(status)`), it prints a message and exits the loop.
    - If the child is stopped because of `SIGTRAP`, the program gets the child’s registers with `ptrace(PTRACE_GETREGS)` to find the instruction pointer (`regs.rip`).
    - It reads the instruction bytes from the child’s memory into the `code` buffer using `ptrace(PTRACE_PEEKTEXT)`.
    - The bytes are then disassembled with Capstone. If successful, it increases the instruction count.
    - It prints the address and details of the disassembled instruction.
    - Finally, it calls `ptrace(PTRACE_SINGLESTEP)` to move to the next instruction. If this fails, it prints an error and exits the loop.