[![Review Assignment Due Date](https://classroom.github.com/assets/deadline-readme-button-22041afd0340ce965d47ae6ef1cefeee28c7c493a6346c4f15d667ab976d596c.svg)](https://classroom.github.com/a/9XFKwmJd)
# The Locks [9-CFU students only]

This assignment aims to familiarize yourself with advanced static-analysis techniques and tools.

In AulaWeb you'll find `the-locks_student_binaries.tar.xz`, containing two different executables for each student (that has linked their account with our GitHub classroom).

As file names suggest, the difficulty of "picking a lock" (=finding the correct password to get a flag back) grows as the level increases.

Of course, you must only analyze your two custom files, identified by your GitHub username, and ignore the others.

So, you must find the flags for level-1 and level-2. For each one:

1. Describe how you analyzed the program; that is, which tools (Ghidra, gdb, ...) you used and how. You can include annotated screenshots if it helps.
2. When you find the flag, list it in your report and describe how you got it.
3. Provide a Python 3 script that, optionally leveraging pwntools and Unicorn, statically decodes and prints the password in your binary. For this part, we expect a standalone script that we can run from the command line without any particular configuration (except for the presence of pwntools and Unicorn, obviously); in other words, your scripts must not depend on Ghidra(thon) or any other external tools.

Note: Unicorn is probably overkilling for level-1, but required for level-2.

As usual, you must include a report written in English. Please avoid MS/Open/Libre-office formats: a plain ASCII, markdown, or a PDF are fine.
