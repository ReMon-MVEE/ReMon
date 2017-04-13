mov %rdi, %rax
mov %rsi, %rdi
mov %rdx, %rsi
mov %rcx, %rdx
mov %r8, %r10
mov %r9, %r8
mov 8(%rsp), %r9

// We want to report this call to the ptracer so we will clear register
// r12 (which contains the IP-MON key)
push %r12
xor %r12, %r12

syscall

// We might want to use the IP-MON key later (for futex etc)
mov (%rsp), %r12
movq $0, (%rsp)
add $8, %rsp
