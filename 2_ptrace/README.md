[![Review Assignment Due Date](https://classroom.github.com/assets/deadline-readme-button-22041afd0340ce965d47ae6ef1cefeee28c7c493a6346c4f15d667ab976d596c.svg)](https://classroom.github.com/a/h2qaHeeq)
# ptrace

The goal of this assignment is to make acquaintance with `ptrace(2)`.

We include a simple hello-world program, written in assembly, to ease the testing of your programs.

Your C programs must be compiled as 64-bit executables (please provide a suitable `Makefile`), and they will be tested only on 64-bit executables; in other words, don't waste time in handling 32-bit executables.

## Part 1: Instruction counter

Write a C program, called `instruction_counter.c`, that

* takes, as command-line arguments, the name of another program and its arguments
* runs such a program, say *P*
* prints how many machine code instructions the execution of *P* consisted of

Example:

```
$ ./instruction_counter /bin/ls -l
Tracing /bin/ls

[...output of ls -l...]

Child exited; n_instructions=1070223
```

Yes, that is an actual output, corresponding to running a simple `ls -l`! Your mileage may, of course, vary.

Please do note that, for non-trivial programs, the instruction count may vary from one execution to another for subtle reasons. For instance, string functions (e.g., strlen, and strcmp) in glibc use special optimized instructions (PMOVMSKB, PCMPEQB, ...) that work with operands of 16 bytes.
These instructions cannot be used when the involved addresses are near the end of a page because this would cross the page boundary and the next page could be unmapped, and the use of these instructions could result in a page fault.
See, for instance, [strlen](https://code.woboq.org/userspace/glibc/sysdeps/x86_64/strlen.S.html#89):

```x86asm
        andq        $4095, %rcx
/* Offsets 4032-4047 will be aligned into 4032 thus fit into page.  */
        cmpq        $4047, %rcx
/* We cannot unify this branching as it would be ~6 cycles slower.  */
        ja        L(cross_page)
```

Since the kernel normally randomizes the stack position, see [linux sources](https://elixir.bootlin.com/linux/latest/source/arch/arm64/kernel/process.c#L542):

```c
unsigned long arch_align_stack(unsigned long sp)
{
        if (!(current->personality & ADDR_NO_RANDOMIZE) && randomize_va_space)
                sp -= get_random_int() & ~PAGE_MASK;
        return sp & ~0xf;
}
```

the same program, running in the same environment, receives its arguments (and environment variables) via the stack at different addresses in different executions and, this causes its instruction streams to be different.

## Part 2: Dynamic disassembler

Write a second C program, called `dynamic_disasm.c`, that

* takes, as command-line arguments, the name of another program and its arguments
* runs such a program, say *P*
* prints, for each machine code instruction executed by *P*, its RIP and assembly mnemonic

Example:

```
$ ./dynamic_disasm ./hello64
0x4000b0: mov  eax, 1
0x4000b5: mov  edi, 1
0x4000ba: movabs  rsi, 0xbadc0ff3badc0d3
0x4000c4: movabs  rsi, 0x6000e4
0x4000ce: mov  edx, 0xc
0x4000d3: syscall
Hello World
0x4000d5: mov  eax, 0x3c
0x4000da: mov  edi, 0
0x4000df: syscall
Child exited; n_instructions=9
```

You must use [Capstone](http://www.capstone-engine.org/), a lightweight multi-platform, multi-architecture disassembly framework to obtain the assembly mnemonics.

On Ubuntu you can install Capstone via apt: `sudo apt-get install libcapstone-dev` (this should also install libcapstone3).
Don't include any Capstone's header/library file in your git repository; we will test your submissions on a system where Capstone is already installed.

See the [Captstone tutorial](https://www.capstone-engine.org/lang_c.html) for an example of how to get the assembly mnemonics from machine-code instructions.
