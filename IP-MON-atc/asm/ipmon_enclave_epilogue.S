/* We added an empty stack slot to correspond to the unused return address, fix that: */
add $8, %rsp

pop %r8 /* This is just to offset the push %r9 that serves as arg6, we could also merge this in the above add */

pop %r12
pop %r13

/* Don't leak the Replication Buffer Pointer */
xor %r11, %r11

mov %rbp, %rsp
pop %rbp

ret
