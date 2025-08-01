;PUBLIC  asmVmexitHandler


extern MainVmexitHandler : proc
extern StopExecution : proc



.code

asmVmexitHandler proc

  
    ; Save general-purpose registers
    push r15
    push r14
    push r13
    push r12
    push r11
    push r10
    push r9
    push r8
    push rdi
    push rsi
    push rbp

    push rbx
    push rdx
    push rcx
    push rax

    ; Pass GuestRegs (current RSP points to GuestRegs) to MainVmexitHandler
    mov rcx, rsp    

    ; Reserve shadow space (Windows x64 calling convention)
    sub rsp, 20h

    ; Call the C handler
    call MainVmexitHandler

    ; Restore stack
    add rsp, 20h

    ; Restore general-purpose registers
    pop rax
    pop rcx
    pop rdx
    pop rbx
    pop rbp
    pop rsi
    pop rdi
    pop r8
    pop r9
    pop r10
    pop r11
    pop r12
    pop r13
    pop r14
    pop r15


asmVmexitHandler endp








END
