	section .text
	global main

main:
    mov rax, 1      ; use the write syscall
    mov rdi, 1      ; write to stdout
    mov rsi, 0xbadc0ff3badc0d3
    mov rsi, msg    ; use string "Hello World"
    mov rdx, msglen ; write 12 characters
    syscall         ; make syscall

    mov rax, 60     ; use the exit syscall
    mov rdi, 0      ; error code 0
    syscall         ; make syscall

	section .data
msg:	db "Hello World", 10
msglen equ $-msg

