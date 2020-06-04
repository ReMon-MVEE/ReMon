/*
 * GHent University Multi-Variant Execution Environment (GHUMVEE)
 *
 * This source file is distributed under the terms and conditions 
 * found in GHUMVEELICENSE.txt.
 */

/*-----------------------------------------------------------------------------
    Includes
-----------------------------------------------------------------------------*/
#include "MVEE_build_config.h"
#include "MVEE.h"
#include "MVEE_private_arch.h"
#include <fstream>
#include <sstream>
#include <assert.h>
#include <stdlib.h>
#include <unistd.h>

/*-----------------------------------------------------------------------------
    add_library_path -
-----------------------------------------------------------------------------*/
void mvee::add_library_path(const char* library_path, bool append_arch_suffix, bool prepend_mvee_root)
{
	std::stringstream ss;

	if (!(*mvee::config_variant_exec)["library_path"].isNull())
		ss << (*mvee::config_variant_exec)["library_path"].asString() << ":";

    if (prepend_mvee_root)
    {
        ss << os_get_mvee_root_dir();
        ss << "/";
    }
    ss << library_path;
    if (append_arch_suffix)
    {
        ss << MVEE_ARCH_SUFFIX;
        ss << "/";
    }

	(*mvee::config_variant_exec)["library_path"] = ss.str();	
}

/*-----------------------------------------------------------------------------
    init_config_set_defaults
-----------------------------------------------------------------------------*/
void mvee::init_config_set_defaults()
{
#define WEAK_INIT_KEY(key, value) if (!key) key = value;

	WEAK_INIT_KEY(config["variant"]["global"]["settings"]["xchecks_initially_enabled"], true);
	WEAK_INIT_KEY(config["variant"]["global"]["settings"]["relaxed_mman_xchecks"], false);
	WEAK_INIT_KEY(config["variant"]["global"]["settings"]["disable_syscall_checks"], false); // also used in RAVEN
	WEAK_INIT_KEY(config["variant"]["global"]["settings"]["use_ipmon"], false);
	WEAK_INIT_KEY(config["variant"]["global"]["settings"]["hide_vdso"], true);
	WEAK_INIT_KEY(config["variant"]["global"]["settings"]["intercept_tsc"], true);
	WEAK_INIT_KEY(config["variant"]["global"]["settings"]["non_overlapping_mmaps"], 0); // also used in RAVEN
	WEAK_INIT_KEY(config["variant"]["global"]["settings"]["allow_setaffinity"], false);
	WEAK_INIT_KEY(config["variant"]["global"]["settings"]["use_system_libc"], false);
	WEAK_INIT_KEY(config["variant"]["global"]["settings"]["use_system_libgomp"], false);
	WEAK_INIT_KEY(config["variant"]["global"]["settings"]["use_system_libstdcpp"], false);
	WEAK_INIT_KEY(config["variant"]["global"]["settings"]["use_system_libgfortran"], true);
	WEAK_INIT_KEY(config["variant"]["global"]["settings"]["use_system_gnomelibs"], false);
	WEAK_INIT_KEY(config["variant"]["global"]["settings"]["performance_counting_enabled"], false);
	WEAK_INIT_KEY(config["variant"]["global"]["settings"]["have_many_threads"], false);
	WEAK_INIT_KEY(config["variant"]["global"]["settings"]["mvee_controlled_aslr"], 0);
	WEAK_INIT_KEY(config["monitor"]["log_to_stdout"], false);
	WEAK_INIT_KEY(config["monitor"]["libc_path"]["path"], "/patched_binaries/libc/");
	WEAK_INIT_KEY(config["monitor"]["libc_path"]["is_absolute"], false);
	WEAK_INIT_KEY(config["monitor"]["libgomp_path"]["path"], "/patched_binaries/libgomp/");
	WEAK_INIT_KEY(config["monitor"]["libgomp_path"]["is_absolute"], false);
	WEAK_INIT_KEY(config["monitor"]["libstdcpp_path"]["path"], "/patched_binaries/libstdc++/");
	WEAK_INIT_KEY(config["monitor"]["libstdcpp_path"]["is_absolute"], false);	
	WEAK_INIT_KEY(config["monitor"]["libgfortran_path"]["path"], "/patched_binaries/libgfortran/");
	WEAK_INIT_KEY(config["monitor"]["libgfortran_path"]["is_absolute"], false);
	WEAK_INIT_KEY(config["monitor"]["gnomelibs_path"]["path"], "/patched_binaries/gnomelibs/");
	WEAK_INIT_KEY(config["monitor"]["gnomelibs_path"]["is_absolute"], false);
	WEAK_INIT_KEY(config["monitor"]["spec_path"]["path"], "/ext/spec2006/");
	WEAK_INIT_KEY(config["monitor"]["spec_path"]["is_absolute"], false);
	WEAK_INIT_KEY(config["monitor"]["parsec2_path"]["path"], "/ext/parsec-2.1/");
	WEAK_INIT_KEY(config["monitor"]["parsec2_path"]["is_absolute"], false);
	WEAK_INIT_KEY(config["monitor"]["parsec3_path"]["path"], "/ext/parsec-3.0/");
	WEAK_INIT_KEY(config["monitor"]["parsec3_path"]["is_absolute"], false);

	config_variant_global = &config["variant"]["global"]["settings"];
	config_variant_exec   = &config["variant"]["global"]["exec"];
	config_monitor        = &config["monitor"];

	if (!(*mvee::config_variant_global)["use_system_libc"].asBool())
	{
		bool is_relative = !(*mvee::config_monitor)["libc_path"]["is_absolute"].asBool();
        mvee::add_library_path((*mvee::config_monitor)["libc_path"]["path"].asCString(),
							   is_relative, is_relative);
	}
    if (!(*mvee::config_variant_global)["use_system_libstdcpp"].asBool())
	{
		bool is_relative = !(*mvee::config_monitor)["libstdcpp_path"]["is_absolute"].asBool();
        mvee::add_library_path((*mvee::config_monitor)["libstdcpp_path"]["path"].asCString(),
							   is_relative, is_relative);
	}
    if (!(*mvee::config_variant_global)["use_system_libgomp"].asBool())
	{
		bool is_relative = !(*mvee::config_monitor)["libgomp_path"]["is_absolute"].asBool();
        mvee::add_library_path((*mvee::config_monitor)["libgomp_path"]["path"].asCString(),
							   is_relative, is_relative);
	}
	if (!(*mvee::config_variant_global)["use_system_libgfortran"].asBool())
	{
		bool is_relative = !(*mvee::config_monitor)["libgfortran_path"]["is_absolute"].asBool();
        mvee::add_library_path((*mvee::config_monitor)["libgfortran_path"]["path"].asCString(),
							   is_relative, is_relative);
	}
    if (!(*mvee::config_variant_global)["use_system_gnomelibs"].asBool())
	{
		bool is_relative = !(*mvee::config_monitor)["gnomelibs_path"]["is_absolute"].asBool();
        mvee::add_library_path((*mvee::config_monitor)["gnomelibs_path"]["path"].asCString(), 
							   is_relative, is_relative);
	}
}

/*-----------------------------------------------------------------------------
    init_config
-----------------------------------------------------------------------------*/
void mvee::init_config()
{
	std::ifstream file(config_file_name);

	if (file.good())
	{
		Json::Reader reader(Json::Features::all());
		if (!reader.parse(file, config, false))
			warnf("Couldn't parse config file: %s\n", config_file_name.c_str());
	}
	else
	{
		warnf("Couldn't read config file: %s\n", config_file_name.c_str());
	}

	init_config_set_defaults();
}

/*-----------------------------------------------------------------------------
    get_spec_profile -
-----------------------------------------------------------------------------*/
const char* mvee::get_spec_profile(bool native)
{
//	if (native)
//		return SPECPROFILENOPIE;
	return SPECPROFILEPIE;
}

/*-----------------------------------------------------------------------------
    set_builtin_config - 
-----------------------------------------------------------------------------*/
void mvee::set_builtin_config(int builtin)
{
    const char* parsec_bench  = NULL;
    const char* parsec_config = NULL;
    const char* splash_bench  = NULL;
    const char* spec_bench    = NULL;
	char parsec_ver = 2;
	bool native = (*mvee::config_variant_global)["disable_syscall_checks"].asBool();

    switch(builtin)
    {
        // Simply runs the ls command. Orchestra can't handle this demo because of the ioctl syscall...
        case 0:
		{
			(*config_variant_exec)["path"] = "/bin/ls";
			(*config_variant_exec)["argv"][0] = "-al";
			(*config_variant_exec)["argv"][1] = "MVEE";
            break;
        }
		
		//
		// SPECint 2006 benchmarks
		//
#define REGISTER_SPEC(num, name) case num: { spec_bench = name; break; }
		REGISTER_SPEC(1 , "400.perlbench"  );
		REGISTER_SPEC(2 , "401.bzip2"      );
		REGISTER_SPEC(3 , "403.gcc"        );
		REGISTER_SPEC(4 , "429.mcf"        );
		REGISTER_SPEC(5 , "445.gobmk"      );
		REGISTER_SPEC(6 , "456.hmmer"      );
		REGISTER_SPEC(7 , "458.sjeng"      );
		REGISTER_SPEC(8 , "462.libquantum" );
		REGISTER_SPEC(9 , "464.h264ref"    );
		REGISTER_SPEC(10, "471.omnetpp"    );
		REGISTER_SPEC(11, "473.astar"      );
		REGISTER_SPEC(12, "483.xalancbmk"  );

		// 
		// SPECfp 2006 benchmarks
		//
		REGISTER_SPEC(13, "410.bwaves"     );
		REGISTER_SPEC(14, "416.gamess"     );
		REGISTER_SPEC(15, "433.milc"       );
		REGISTER_SPEC(16, "434.zeusmp"     );
		REGISTER_SPEC(17, "435.gromacs"    );
		REGISTER_SPEC(18, "436.cactusADM"  );
		REGISTER_SPEC(19, "437.leslie3d"   );
		REGISTER_SPEC(20, "444.namd"       );
		REGISTER_SPEC(21, "447.dealII"     );
		REGISTER_SPEC(22, "450.soplex"     );
		REGISTER_SPEC(23, "453.povray"     );
		REGISTER_SPEC(24, "454.calculix"   );
		REGISTER_SPEC(25, "459.GemsFDTD"   );
		REGISTER_SPEC(26, "465.tonto"      );
		REGISTER_SPEC(27, "470.lbm"        );
		REGISTER_SPEC(28, "481.wrf"        );
		REGISTER_SPEC(29, "482.sphinx3"    );

		//
		// PARSEC benchmarks
		//
#define REGISTER_PARSEC(num, ver, config, name) case num: { parsec_bench = name; parsec_ver = ver; parsec_config = config; break; }
		REGISTER_PARSEC(30, 2, "gcc-pthreads", "blackscholes"  );
		REGISTER_PARSEC(31, 2, "gcc-pthreads", "bodytrack"     );
		REGISTER_PARSEC(32, 2, "gcc-pthreads", "canneal"       );
		REGISTER_PARSEC(33, 2, "gcc-pthreads", "dedup"         );
		REGISTER_PARSEC(34, 3, "gcc-pthreads", "facesim"       );
		REGISTER_PARSEC(35, 3, "gcc-pthreads", "ferret"        );
		REGISTER_PARSEC(36, 2, "gcc-pthreads", "fluidanimate"  );
		REGISTER_PARSEC(37, 2, "gcc-openmp"  , "freqmine"      );
		REGISTER_PARSEC(38, 2, "gcc-pthreads", "raytrace"      );
		REGISTER_PARSEC(39, 3, "gcc-pthreads", "streamcluster" );
		REGISTER_PARSEC(40, 2, "gcc-pthreads", "swaptions"     );
		REGISTER_PARSEC(41, 2, "gcc-pthreads", "vips"          );
		REGISTER_PARSEC(42, 2, "gcc-pthreads", "x264"          );

		// 
		// SPLASH-2x benchmarks
		//
#define REGISTER_SPLASH(num, name) case num: { splash_bench = name; break; }
		REGISTER_SPLASH(43, "splash2x.barnes"         ); 
		REGISTER_SPLASH(44, "splash2x.cholesky"       ); 
		REGISTER_SPLASH(45, "splash2x.fft"            ); 
		REGISTER_SPLASH(46, "splash2x.fmm"            ); 
		REGISTER_SPLASH(47, "splash2x.lu_cb"          ); 
		REGISTER_SPLASH(48, "splash2x.lu_ncb"         ); 
		REGISTER_SPLASH(49, "splash2x.ocean_cp"       ); 
		REGISTER_SPLASH(50, "splash2x.ocean_ncp"      ); 
		REGISTER_SPLASH(51, "splash2x.radiosity"      ); 
		REGISTER_SPLASH(52, "splash2x.radix"          ); 
		REGISTER_SPLASH(53, "splash2x.raytrace"       ); 
		REGISTER_SPLASH(54, "splash2x.volrend"        ); 
		REGISTER_SPLASH(55, "splash2x.water_nsquared" ); 
		REGISTER_SPLASH(56, "splash2x.water_spatial"  ); 
    }

    if (parsec_bench || splash_bench)
    {
		assert(!(*mvee::config_variant_exec)["argv"].isNull());
		auto arg_tokens = mvee::strsplit((*mvee::config_variant_exec)["argv"][0].asCString(), ' ');
        assert(arg_tokens.size() >= 2);

		std::stringstream cmd;
		Json::Value spec_path = (parsec_ver == 2 && !splash_bench) ?
			(*mvee::config_monitor)["parsec2_path"] :
			(*mvee::config_monitor)["parsec3_path"];

		if (!spec_path["is_absolute"].asBool())			
			cmd << os_get_mvee_root_dir();
		cmd << spec_path["path"].asString();
		
        if ((*mvee::config_variant_global)["performance_counting_enabled"].asBool())
			cmd << "/bin/parsecmgmt-perf";
		else
			cmd << "/bin/parsecmgmt";

		if (access(cmd.str().c_str(), F_OK) == -1)
		{
			printf("ERROR: Could not find PARSEC/SPLASH management script at:\n   %s\n", cmd.str().c_str());
			return;
		}

		std::string numthreads = arg_tokens[0];
		std::string input      = arg_tokens[1];

		(*config_variant_exec)["path"] = "/bin/bash";
		(*config_variant_exec)["argv"][0] = cmd.str();
		(*config_variant_exec)["argv"][1] = "-a";
		(*config_variant_exec)["argv"].append("run");
		(*config_variant_exec)["argv"].append("-p");
		(*config_variant_exec)["argv"].append(parsec_bench ? parsec_bench : splash_bench);
		(*config_variant_exec)["argv"].append("-n");
		(*config_variant_exec)["argv"].append(numthreads);
		(*config_variant_exec)["argv"].append("-i");
		(*config_variant_exec)["argv"].append(input);
		(*config_variant_exec)["argv"].append("-c");
		(*config_variant_exec)["argv"].append(parsec_config ? parsec_config : "gcc-pthreads");	   
#ifdef SYNCTRACE_LIB
        if (!synctrace_logfile.empty())
        {
            (*config_variant_exec)["argv"].append("-s");
            std::stringstream dynamorio_cmd;
            dynamorio_cmd << DYNAMORIO_DIR << "/bin64/drrun -c " << SYNCTRACE_LIB << " --log_file " << synctrace_logfile << " --";
            (*config_variant_exec)["argv"].append(dynamorio_cmd.str());
        }
#endif
    }
    else if (spec_bench)
    {
		std::stringstream cmd, specpath, benchpath;

		// check if we can find the runme script
		cmd << os_get_mvee_root_dir()
		    << "/MVEE/bin/Release/spec/" 
			<< spec_bench << "/ref/runme.sh";

		if (access(cmd.str().c_str(), F_OK) == -1)
		{
			printf("ERROR: Could not find SPEC runme script at:\n  %s\n",
				   cmd.str().c_str());
			return;
		}

		// check if SPEC is installed
		Json::Value tmp = (*mvee::config_monitor)["spec_path"];
		if (!tmp["is_absolute"].asBool())
			specpath << os_get_mvee_root_dir();
		
		specpath << tmp["path"].asString();

		if (access(specpath.str().c_str(), F_OK) == -1)
		{
			printf("ERROR: Could not find SPEC folder at:\n  %s\n",
				   specpath.str().c_str());
			return;
		}

		// check if the binaries are installed
		benchpath << specpath.str()
				  << "/benchspec/CPU2006/"
				  << spec_bench
				  << "/build/"
				  << get_spec_profile(native);

		if (access(specpath.str().c_str(), F_OK) == -1)
		{
			printf("ERROR: Could not find SPEC build folder at:\n  %s\n",
				   specpath.str().c_str());
			return;
		}

		(*config_variant_exec)["path"] = "/bin/bash";
		(*config_variant_exec)["argv"][0] = cmd.str();
		(*config_variant_exec)["env"][0] = std::string("SPEC=") + specpath.str();
		(*config_variant_exec)["env"].append(std::string("SPECPATH=") + specpath.str() + std::string("benchspec/CPU2006"));
		(*config_variant_exec)["env"].append(std::string("SPECLIBPATH=") + specpath.str() + std::string("bin/lib"));
		(*config_variant_exec)["env"].append(std::string("SPECPROFILE=") + get_spec_profile(native));
    }

	if (builtin == 42) // x264
		(*mvee::config_variant_global)["have_many_threads"] = true;	
}

