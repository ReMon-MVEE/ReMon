/*
 * GHent University Multi-Variant Execution Environment (GHUMVEE)
 *
 * This source file is distributed under the terms and conditions 
 * found in GHUMVEELICENSE.txt.
 */

//
// DO NOT INCLUDE THIS FILE DIRECTLY!!!! INCLUDE MVEE_MONITOR.H INSTEAD
//
// These templates are inlined into the monitor class
//

/*-----------------------------------------------------------------------------
  arg - returns a reference to the specified syscall argument.
  The ARG<n> macros are platform-specific and implemented in MVEE_private_arch.h
-----------------------------------------------------------------------------*/
template<int N> constexpr 
MVEE_ARCH_REG_TYPE& arg(int variantnum)
{
	switch(N)
	{
		case 1: return ARG1(variantnum);
		case 2: return ARG2(variantnum);
		case 3: return ARG3(variantnum);
		case 4: return ARG4(variantnum);
		case 5: return ARG5(variantnum);		
		case 6: return ARG6(variantnum);
	}

	return ARG6(variantnum);
}

/*-----------------------------------------------------------------------------
  arg64 - calculates the value of a 64-bit argument
-----------------------------------------------------------------------------*/
template<int base, int aligned> constexpr
unsigned long long arg64(int variantnum)
{
	unsigned long long first_half = 0, second_half = 0;
	int real_base = base;
	
#ifdef MVEE_ARCH_IS_64BIT
	switch(base)
	{
		case 1: return ARG1(variantnum);
		case 2: return ARG2(variantnum);
		case 3: return ARG3(variantnum);
		case 4: return ARG4(variantnum);
		case 5: return ARG5(variantnum);		
		case 6: return ARG6(variantnum);
	}
#elif defined(MVEE_ARCH_REQUIRES_REG_ALIGNMENT)
	real_base = aligned;
#endif

	switch(real_base)
	{
		case 1:
		{
			first_half = ARG1(variantnum);
			second_half = ARG2(variantnum);
			break;
		}
		case 2:
		{
			first_half = ARG2(variantnum);
			second_half = ARG3(variantnum);
			break;
		}
		case 3:
		{
			first_half = ARG3(variantnum);
			second_half = ARG4(variantnum);
			break;
		}
		case 4:
		{
			first_half = ARG4(variantnum);
			second_half = ARG5(variantnum);
			break;
		}
		case 5:
		{
			first_half = ARG5(variantnum);
			second_half = ARG6(variantnum);
			break;
		}
		default:
		{
			warnf("syscall arg [%d:%d] does not exist!\n",
				  real_base, real_base + 1);
			return 0;
		}
	}

#ifdef MVEE_ARCH_LITTLE_ENDIAN
	return first_half + (second_half << 32);
#else
	return (first_half << 32) + second_half;
#endif
}

/*-----------------------------------------------------------------------------
  aligned_arg
-----------------------------------------------------------------------------*/
template<int base, int aligned> constexpr
MVEE_ARCH_REG_TYPE& aligned_arg(int variantnum)
{
	int real_base = base;

#if defined(MVEE_ARCH_REQUIRES_REG_ALIGNMENT) && !defined(MVEE_ARCH_IS_64_BIT)
	real_base = aligned;
#endif
	
	switch(real_base)
	{
		case 1: return ARG1(variantnum);
		case 2: return ARG2(variantnum);
		case 3: return ARG3(variantnum);
		case 4: return ARG4(variantnum);
		case 5: return ARG5(variantnum);		
		case 6: return ARG6(variantnum);
	}

	return ARG6(variantnum);
}

/*-----------------------------------------------------------------------------
  get_arg_array - 
-----------------------------------------------------------------------------*/
template<typename T, int N>
    std::vector<T> get_arg_array()
{
	std::vector<T> args(mvee::numvariants);
	for (int i = 0; i < mvee::numvariants; ++i)
		args[i] = *reinterpret_cast<T*>(&arg<N>(i));
	return args;
}

/*-----------------------------------------------------------------------------
  call_do_alias_at - applies aliasing to the arguments of a syscall accepting
  a file path argument. If the monitor configuration specifies an alias for
  the file being opened, the file path argument is overwritten and the function
  will return true.  
-----------------------------------------------------------------------------*/
template<int dirarg, int patharg> 
    bool call_do_alias_at()
{
	bool result = false;
	int limit = 1;

	// for mastercalls, only apply aliasing to the master variant's arguments
	if (state != STATE_IN_MASTERCALL)
		limit = mvee::numvariants;

	for (int i = 0; i < limit; ++i)
	{
		auto orig_path = set_fd_table->get_full_path(i, variants[i].variantpid, 
													 (unsigned long) arg<dirarg>(i), (void*) arg<patharg>(i));
		auto alias = mvee::get_alias(i, orig_path);
		if (alias != "")
		{
			debugf("%s - File %s is aliased to %s\n", 
				   call_get_variant_pidstr(i).c_str(), orig_path.c_str(), alias.c_str());
			call_overwrite_arg_data(i, patharg, orig_path.length() + 1, 
									(void*) alias.c_str(), alias.length() + 1, true);
			result = true;
		}
	}

	return result;
}

/*-----------------------------------------------------------------------------
  call_do_alias - Same thing as above, but to be used for the "old" syscalls
  that do not accept a separate dirfd argument
-----------------------------------------------------------------------------*/
template<int patharg> 
    bool call_do_alias()
{
	bool result = false;
	int limit = 1;

	// for mastercalls, only apply aliasing to the master variant's arguments
	if (state != STATE_IN_MASTERCALL)
		limit = mvee::numvariants;

	for (int i = 0; i < limit; ++i)
	{
		auto orig_path = set_fd_table->get_full_path(i, variants[i].variantpid, 
													 AT_FDCWD, (void*) arg<patharg>(i));
		auto alias = mvee::get_alias(i, orig_path);
		if (alias != "")
		{
			debugf("%s - File %s is aliased to %s\n", 
				   call_get_variant_pidstr(i).c_str(), orig_path.c_str(), alias.c_str());
			call_overwrite_arg_data(i, patharg, orig_path.length() + 1, 
									(void*) alias.c_str(), alias.length() + 1, true);
			result = true;
		}
	}

	return result;
}
