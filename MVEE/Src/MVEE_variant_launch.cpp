/*
 * GHent University Multi-Variant Execution Environment (GHUMVEE)
 *
 * This source file is distributed under the terms and conditions 
 * found in GHUMVEELICENSE.txt.
 */

/*-----------------------------------------------------------------------------
    Includes
-----------------------------------------------------------------------------*/
#include <unistd.h>
#include <stdlib.h>
#include <sstream>
#include "MVEE.h"
#include "MVEE_monitor.h"

/*-----------------------------------------------------------------------------
    parse_and_setenv - 
-----------------------------------------------------------------------------*/
static void parse_and_setenv(std::string env)
{
	size_t pos = env.find("=");
	if (pos != std::string::npos)
	{
		std::string key   = env.substr(0, pos);
		std::string value = env.substr(pos + 1);

		if (value.length() > 0)
		{
			const char* oldenv = getenv(key.c_str());
			if (oldenv)
				setenv(key.c_str(), (value + ":" + oldenv).c_str(), 1);
			else
				setenv(key.c_str(), value.c_str(), 1);
		}
		else
			unsetenv(key.c_str());
	}	
}

/*-----------------------------------------------------------------------------
    setup_env - sets up the environment for the variant to run in.

    This code is executed by the variants, BEFORE the monitor is attached
-----------------------------------------------------------------------------*/
void mvee::setup_env(int variantnum)
{
	// Set the library path directly if we're going to run unmonitored variants
	if ((*mvee::config_variant_global)["disable_syscall_checks"].asBool())
	{
		setenv("LD_LIBRARY_PATH", (*mvee::config_variant_exec)["library_path"].asCString(), 1);
	}
	else
	{
		if ((*mvee::config_variant_global)["use_ipmon"].asBool())
		{
			std::string ipmon_path = os_get_mvee_root_dir();
			ipmon_path += "/IP-MON/libipmon.so";
			setenv("LD_PRELOAD", mvee::strdup(ipmon_path.c_str()), 1);
		}
	}
   
	// needed by LD_Loader and SPEC scripts
	setenv("MVEEROOT", os_get_mvee_root_dir().c_str(), 1);

	// per-variant env variables take precedence over global env vars
	if (!mvee::config["variant"]["specs"] ||
		!mvee::config["variant"]["specs"][mvee::variant_ids[variantnum]] ||
		!mvee::config["variant"]["specs"][mvee::variant_ids[variantnum]]["env"])
	{
		for (auto envp : (*mvee::config_variant_exec)["env"])
			parse_and_setenv(envp.asString());
	}
	else
	{
		for (auto envp : mvee::config["variant"]["specs"][mvee::variant_ids[variantnum]]["env"])
			parse_and_setenv(envp.asString());
	}
}

/*-----------------------------------------------------------------------------
    start_variant
-----------------------------------------------------------------------------*/
void mvee::start_variant(int variantnum)
{
	std::deque<const char*> args;
	Json::Value* variant_config = NULL;

	// See if we have a variant-specific config that might contain program args
	if (!mvee::config["variant"]["specs"].isNull() &&
		!mvee::config["variant"]["specs"][mvee::variant_ids[variantnum]].isNull())
		variant_config = &mvee::config["variant"]["specs"][mvee::variant_ids[variantnum]];	   		

	// per-variant argvs take precedence over global argvs
	if (!variant_config || !(*variant_config)["argv"])
	{
		for (auto arg : (*mvee::config_variant_exec)["argv"])
			args.push_back(mvee::strdup(arg.asCString()));
	}
	else
	{
		for (auto arg : (*variant_config)["argv"])
			args.push_back(mvee::strdup(arg.asCString()));
	}
	args.push_back(NULL);

    // get absolute path of the binary to start
	std::string binary;
	if (!variant_config || !(*variant_config)["path"])
		binary = (*mvee::config_variant_exec)["path"].asString();
	else
		binary = (*variant_config)["path"].asString();

	// apply aliasing
	std::string alias = get_alias(variantnum, binary);
	if (alias.length() == 0)
		alias = binary;

	// this might be a relative path. Get the full path
	alias = os_normalize_path_name(alias);

	// push the basename of the original binary name as argv[0]
	size_t pos = binary.rfind("/");
	if (pos != std::string::npos)
		args.push_front(mvee::strdup(binary.substr(pos+1).c_str()));
	else
		args.push_front(mvee::strdup(binary.c_str()));

	// Build arg array
	const char** _args = new const char*[args.size()];
	int i = 0;
	for (auto _arg : args)
		_args[i++] = _arg;

	// change to the variant's specified working directory (if any)
	if (variant_config && !(*variant_config)["pwd"].isNull())
	{
		if (chdir((*variant_config)["pwd"].asCString()))
		{
			warnf("Failed to change to specified working directory - error: %s\n",
				getTextualErrno(errno));
			return;
		}
	}

	// this should not return
	execv(alias.c_str(), (char* const*)_args);

	printf("ERROR: Failed to start variant: %s (argv: [", binary.c_str());
	i = 0;
	for (auto _arg : args)
	{
		if (i++ > 0) printf(", ");
		printf("%s", _arg);
	}
	printf("])\n");
}
