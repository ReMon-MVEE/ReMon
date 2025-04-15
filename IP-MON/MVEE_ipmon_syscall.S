/*
 * GHent University Multi-Variant Execution Environment (GHUMVEE)
 *
 * This source file is distributed under the terms and conditions 
 * found in IPMONLICENSE.txt.
 */

/*-----------------------------------------------------------------------------
    Convenience Macros
-----------------------------------------------------------------------------*/
#define FUNCTION_START(name)			\
		.globl name;					\
		.type name,@function;			\
		.hidden name;					\
		.cfi_startproc;					\
		.align 16;						\
name:

#define FUNCTION_END(name);             \
		.cfi_endproc;					\
		.size name,.-name

#define FUNCTION_START_EXPORTED(name)   \
		.globl name;                    \
		.type name,@function;           \
		.cfi_startproc;                 \
		.align 16;                      \
name:

#define SYMBOL(name)			\
		.globl name;					\
		.hidden name;					\
name:

#define MAX_ERRNO 4095

/*-----------------------------------------------------------------------------
    Global Variables
-----------------------------------------------------------------------------*/
		.section .data
		.globl ipmon_initialized
		.hidden ipmon_initialized;		\
ipmon_initialized:
		.byte 0


		.section .text
		.intel_syntax noprefix


/*-----------------------------------------------------------------------------
	ipmon_unchecked_syscall - Perform a syscall without oversight, will not pass
	by the tracer.

	Without BPF: The IP-MON key now always "lives" in register r12. We prevent
	the compiler from moving it/overwriting it by passing -ffixed-r12 on the
	command line.

	Therefore, we don't have to do anything special to request an unchecked
	syscall. This is now the default. Do note, however, that the IP-MON key can now
	be used only once.

	With BPF: The filter knows the instruction pointer of the unchecked syscall
	address so it evaluates to return a SECCOMP_RET_ALLOW action.

TODO:	 This function should be inlined in the C code!!
-----------------------------------------------------------------------------*/
FUNCTION_START(ipmon_unchecked_syscall)
		mov rax, rdi
		mov rdi, rsi
		mov rsi, rdx
		mov rdx, rcx
		mov r10, r8
		mov r8, r9
		mov r9, QWORD PTR [rsp + 8]
		syscall
SYMBOL(ipmon_unchecked_syscall_ret)
		ret
FUNCTION_END(ipmon_unchecked_syscall)

/*-----------------------------------------------------------------------------
	ipmon_checked_syscall - Perform a syscall with oversight, this will pass by
	the tracer.

	Without BPF: We explicitly clear register r12 here so as to force the kernel
	to report this syscall to the ptracer.

	With BPF: The filter knows the instruction pointer of the checked syscall
	address so it evaluates to return a SECCOMP_RET_TRACE action.

TODO:	This function should be inlined in the C code!!
-----------------------------------------------------------------------------*/
FUNCTION_START(ipmon_checked_syscall)
		mov rax, rdi
		mov rdi, rsi
		mov rsi, rdx
		mov rdx, rcx
		mov r10, r8
		mov r8, r9
		mov r9, QWORD PTR [rsp + 8]
		
#ifndef IPMON_USE_BPF
		// We want to report this call to the ptracer so we will clear register
        // r12 (which contains the IP-MON key)
		push r13
		.cfi_adjust_cfa_offset 8
		.cfi_offset r13, -16
		mov r13, r12
		xor r12, r12
#endif

		syscall
SYMBOL(ipmon_checked_syscall_ret)

#ifndef IPMON_USE_BPF
		// We might want to use the IP-MON key later (for futex etc)
		mov r12, r13
		pop r13
		.cfi_adjust_cfa_offset -8
		.cfi_restore r13
#endif
		
		ret
FUNCTION_END(ipmon_checked_syscall)

#ifndef IPMON_PASS_RB_POINTER_EXPLICITLY
/*-----------------------------------------------------------------------------
    ipmon_enclave_entrypoint - This is where the kernel lands when the app
	executes a syscall that is on the IP-MON whitelist. Incoming arguments are
	as follows:

rax:	original syscall number
rdi:	arg1
rsi:	arg2
rdx:	arg3
r10:	arg4
r8:		arg5
r9:		arg6
r11:	Replication Buffer Pointer     (when not using BPF)
rcx:	IP-MON key                     (when not using BPF)

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
		
r11:	Replication Buffer Pointer     (when not using BPF)
r12:	IP-MON key                     (when not using BPF)
r13:	Reserved                       (when not using BPF)

Outgoing Stack:
		+00 enclave entrypoint return address
		+08 arg6                         (when not using BPF)
-----------------------------------------------------------------------------*/
		.align 4096									// algin 4096 to get the 12 most lsbs to 0
FUNCTION_START_EXPORTED(ipmon_enclave_entrypoint)
		// The callee (ipmon_enclave) will preserve registers rbp,rbx and r12-r15.
		// We are responsible for preserving the rest of the registers except for:
		// rcx,r11 because the kernel is allowed to clobber these
		// rax because this is our syscall return value
		// We must preserve: rdx, rsi, r8, r9, r10, rdi, rsp		

		push rbp
		.cfi_adjust_cfa_offset 8
		push rdx
		.cfi_adjust_cfa_offset 8
		push rsi
		.cfi_adjust_cfa_offset 8
		push r8
		.cfi_adjust_cfa_offset 8
		push r10
		.cfi_adjust_cfa_offset 8
		push rdi
		.cfi_adjust_cfa_offset 8
		mov rbp, rsp
		.cfi_def_cfa_register rbp

		// We need to align the stack
		sub rsp, 16
		and rsp, 0xfffffffffffffff0
		sub rsp, 8
		
#ifndef IPMON_USE_BPF
		push r13
		push r12
		mov r12, rcx // IP-MON key
#endif
		push r9 // syscall arg6 must be arg7 for the enclave C function

		mov r9, r8   // arg5
		mov r8, r10  // arg4
		mov rcx, rdx // arg3
		mov rdx, rsi // arg2
		mov rsi, rdi // arg1
		mov rdi, rax // syscall no
		
		call ipmon_enclave

		pop r9
#ifndef IPMON_USE_BPF
		pop r12
		pop r13

		// Don't leak the Replication Buffer Pointer
		xor r11, r11
#endif

		mov rsp, rbp
		.cfi_def_cfa_register rbp
		pop rdi
		.cfi_adjust_cfa_offset -8
		pop r10
		.cfi_adjust_cfa_offset -8
		pop r8
		.cfi_adjust_cfa_offset -8
		pop rsi
		.cfi_adjust_cfa_offset -8
		pop rdx
		.cfi_adjust_cfa_offset -8
		pop rbp
		.cfi_adjust_cfa_offset -8

		retq
		
FUNCTION_END(ipmon_enclave_entrypoint)

FUNCTION_START(ipmon_seccomp_exchange_address)
	mov [rsp-8], rax                 // Save original syscall number
	syscall                            // Invoke syscall for the first time

SYMBOL(ipmon_exchange_syscall_ret)
	cmpq rax, -MAX_ERRNO
	jne end                           // Go to the exit when tracing with CP-MON

	movq rcx, [rsp-8]                 // Move original syscall number into r12 by way of rcx
	pushq r12
	pushq r13
	pushq r15
	movq r12, rcx                     // Store original syscall number in r12
	movq r13, MAX_ERRNO + 3           // r13 contains the exchange key, will decrements every loop
	xorq r15, r15                     // We will build the entrypoint address in r15

exchange:
	movq rax, r13                     // Load new value of the exchange key in rax to get the next bits of the IP-MON enclave address
	syscall                           // Invoke syscall to get new part
SYMBOL(ipmon_exchange_syscall_ret2)
	neg rax                           // Received the exchange start key as negative errno value, invert the value
	addq r15, rax                     // Add new part to the entrypoint address
	shl r15, 12                       // Shift 12 bits to left, to align with the part of the address we received

	sub r13, 1                        // Decrement exchange key
	cmpq r13, MAX_ERRNO               // We stop at MAX_ERRNO
	jne exchange

	movq rax, r12                     // Restore the original syscall number
	call r15                          // Call IP-MON enclave
	popq r15                          // Overwrite IP-MON's address!
	popq r13
	popq r12

end:
	retq
		
FUNCTION_END(ipmon_seccomp_exchange_address)

#else
/*-----------------------------------------------------------------------------
    ipmon_enclave_entrypoint_alternative - This is an alternative version of
	the enclave entrypoint function. It passes the RB pointer to the C enclave
    as an explicit argument.

Incoming arguments:

rax:	original syscall number
rdi:	arg1
rsi:	arg2
rdx:	arg3
r10:	arg4
r8:		arg5
r9:		arg6
r11:	Replication Buffer Pointer
rcx:	IP-MON key

Outgoing arguments:

rdi:	Replication Buffer Pointer
rsi:	Original Syscall Number
rdx:	arg1
rcx:	arg2
r8:		arg3
r9:		arg4
		
Outgoing Stack:
		+00 enclave entrypoint return address
		+08 arg5
		+16 arg6
-----------------------------------------------------------------------------*/		
FUNCTION_START_EXPORTED(ipmon_enclave_entrypoint_alternative)
		
		push rbp
		.cfi_adjust_cfa_offset 8
		push rdx
		.cfi_adjust_cfa_offset 8
		push rsi
		.cfi_adjust_cfa_offset 8
		push r10
		.cfi_adjust_cfa_offset 8
		push rdi
		.cfi_adjust_cfa_offset 8
		mov rbp, rsp
		.cfi_def_cfa_register rbp

		// align stack
		sub rsp, 16
		and rsp, 0xfffffffffffffff0
		sub rsp, 8
		
		push r12
		mov r12, rcx // IP-MON key

		push r9 // arg6
		push r8 // arg5
		mov r9, r10  // arg4
		mov r8, rdx  // arg3
		mov rcx, rsi // arg2
		mov rdx, rdi // arg1
		mov rsi, rax // syscall no
		mov rdi, r11 // RB pointer
		xor r11, r11

		call ipmon_enclave

		pop r8
		pop r9
		pop r12

		mov rsp, rbp
		.cfi_def_cfa_register rbp
		pop rdi
		.cfi_adjust_cfa_offset -8		
		pop r10
		.cfi_adjust_cfa_offset -8		
		pop rsi
		.cfi_adjust_cfa_offset -8		
		pop rdx
		.cfi_adjust_cfa_offset -8		
		pop rbp
		.cfi_adjust_cfa_offset -8
		
		retq

FUNCTION_END(ipmon_enclave_entrypoint_alternative)
#endif
