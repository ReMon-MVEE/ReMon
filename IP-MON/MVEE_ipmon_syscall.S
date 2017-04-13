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

/*-----------------------------------------------------------------------------
    Global Variables
-----------------------------------------------------------------------------*/
		.section .data
		.globl ipmon_initialized
ipmon_initialized:
		.byte 0


		.section .text
		.intel_syntax noprefix


/*-----------------------------------------------------------------------------
	ipmon_unchecked_syscall - The IP-MON key now always "lives" in register r12.
	We prevent the compiler from moving it/overwriting it by passing -ffixed-r12
	on the command line.

	Therefore, we don't have to do anything special to request an unchecked
	syscall. This is now the default. Do note, however, that the IP-MON key
	can now be used only once.

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
		ret
FUNCTION_END(ipmon_unchecked_syscall)

/*-----------------------------------------------------------------------------
	ipmon_checked_syscall - we explicitly clear register r12 here so as to force
	the kernel to report this syscall to the ptracer

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
		
		// We want to report this call to the ptracer so we will clear register
        // r12 (which contains the IP-MON key)
		push r13
		.cfi_adjust_cfa_offset 8
		.cfi_offset r13, -16
		mov r13, r12
		xor r12, r12
		
		syscall

		// We might want to use the IP-MON key later (for futex etc)
		mov r12, r13
		pop r13
		.cfi_adjust_cfa_offset -8
		.cfi_restore r13
		
		ret
FUNCTION_END(ipmon_checked_syscall)

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
		
r11:	Replication Buffer Pointer
r12:	IP-MON key
r13:	Reserved

Outgoing Stack:
		+00 enclave entrypoint return address
		+08 arg6
-----------------------------------------------------------------------------*/
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
		
		push r13
		push r12
		push r9 // syscall arg6 must be arg7 for the enclave C function
		mov r12, rcx // IP-MON key

		mov r9, r8   // arg5
		mov r8, r10  // arg4
		mov rcx, rdx // arg3
		mov rdx, rsi // arg2
		mov rsi, rdi // arg1
		mov rdi, rax // syscall no
		
		call ipmon_enclave@plt

		pop r9
		pop r12
		pop r13

		// Don't leak the Replication Buffer Pointer
		xor r11, r11

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
		
FUNCTION_END(ipmon_enclave_entrypoint)

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

		call ipmon_enclave@plt

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

