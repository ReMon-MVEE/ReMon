/*-----------------------------------------------------------------------------
    ipmon_enclave_entrypoint's prologue - This is where the kernel lands when the app
	executes a syscall that is on the IP-MON whitelist. Incoming arguments are
	as follows:

rax:	original syscall number
rdi:	arg1
rsi:	arg2
rdx:	arg3
r10:	arg4
r8:		arg5
r9:		arg6
r11:	Replication Buffer Pointer
rcx:	IP-MON key

	In this function, we just do some juggling so we can handle all of the
	replication/checking logic in plain C code.

	The Replication Buffer Pointer is top secret and must never leak to memory.

	Outgoing args:

rdi:	original syscall no
rsi:	arg1
rdx:	arg2
rcx:	arg3
r8:		arg4
r9:		arg5
		
r11:	unused
r12:	IP-MON key
r13:	RB pointer

Outgoing Stack:
		+00 enclave entrypoint return address
		+08 arg6
-----------------------------------------------------------------------------*/

push %rbp
mov %rsp, %rbp
sub $16, %rsp
and $0xfffffffffffffff0, %rsp
sub $8, %rsp

push %r13
mov %r11, %r13
xor %r11, %r11

push %r12
mov %rcx, %r12 /* IP-MON key */

push %r9         /* arg6 */
mov %r8, %r9     /* arg5 */
mov %r10, %r8    /* arg4 */
mov %rdx, %rcx   /* arg3 */
mov %rsi, %rdx   /* arg2 */
mov %rdi, %rsi  /* arg1 */
mov %rax, %rdi  /* syscall no */

/* This is a prologue, but the function itself expects that is being called in a 'regular' fashion, and that its arg6
   argument is one slot beyond (%rsp) which contains the (now-unused) return address, fix that */
sub $8, %rsp
