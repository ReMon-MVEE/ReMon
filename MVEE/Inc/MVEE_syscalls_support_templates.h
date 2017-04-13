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
    unsigned long long int& arg(int variantnum)
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
