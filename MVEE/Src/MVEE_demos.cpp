/*
 * GHent University Multi-Variant Execution Environment (GHUMVEE)
 *
 * This source file is distributed under the terms and conditions 
 * found in GHUMVEELICENSE.txt.
 */

/*-----------------------------------------------------------------------------
    Includes
-----------------------------------------------------------------------------*/
#include <stdlib.h>
#include <assert.h>
#include <sstream>
#include "MVEE.h"
#include "MVEE_monitor.h"
#include "MVEE_private_arch.h"

/*-----------------------------------------------------------------------------
    set_demo_options - sets per-demo options. This includes the
    library path which is now enforced through ld.so --library-path

    This is obviously not that useful when running benchmarks natively...
-----------------------------------------------------------------------------*/
void mvee::set_demo_options(int demonum)
{
    if (!mvee::config.mvee_use_system_libc)
        mvee::add_library_path(mvee::config.mvee_libc_path);
    if (!mvee::config.mvee_use_system_libstdcpp)
        mvee::add_library_path(mvee::config.mvee_libstdcpp_path);
    if (!mvee::config.mvee_use_system_libgomp)
        mvee::add_library_path(mvee::config.mvee_libgomp_path);
    if (!mvee::config.mvee_use_system_gnomelibs)
        mvee::add_library_path(mvee::config.mvee_gnomelibs_path);

	if (demonum == 31 || // bodytrack
		demonum == 36 || // fluidanimate
		demonum == 38 || // raytrace
		demonum == 39 || // streamcluster
		(demonum >= 43 && demonum <= 56)) // SPLASH-2x
		mvee::demo_schedule_type = MVEE_CLEVER_SCHEDULING;

	if (demonum == 42) // x264
		mvee::demo_has_many_threads = true;	
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
    setup_env - sets up the environment for the variant to run in.

    This code is executed by the variants, BEFORE the monitor is attached
-----------------------------------------------------------------------------*/
void mvee::setup_env(int demonum, bool native)
{
    if (mvee::config.mvee_use_ipmon && !native)
    {
        std::string ipmon_path = mvee::config.mvee_root_path;
        ipmon_path += "/IP-MON/libipmon.so";
        setenv("LD_PRELOAD", mvee::strdup(ipmon_path.c_str()), 1);
    }

    if (demonum >= 1 && demonum <= 29)
    {
		std::string spec_path = mvee::config.mvee_root_path;
		spec_path += mvee::config.mvee_spec2006_path;

        setenv("SPEC",        spec_path.c_str(),                                    1);		
        setenv("SPECPATH",    std::string(spec_path + "benchspec/CPU2006").c_str(), 1);
		setenv("SPECLIBPATH", std::string(spec_path + "bin/lib").c_str(),           1);
		setenv("SPECPROFILE", get_spec_profile(native),                             1);
    }

	// export this one for our spec scripts
	setenv("MVEEROOT",    mvee::config.mvee_root_path,                          1);
}

/*-----------------------------------------------------------------------------
    start_demo - This code runs in the variant processes, not in the monitor!!!
-----------------------------------------------------------------------------*/
void mvee::start_demo(int demonum, int variantindex, bool native)
{
    const char* parsec_bench  = NULL;
    const char* parsec_config = NULL;
    const char* splash_bench  = NULL;
    const char* spec_bench    = NULL;
	char parsec_ver = 2;

    switch(demonum)
    {
        // Simply runs the ls command. Orchestra can't handle this demo because of the ioctl syscall...
        case 0:
		{
            execl("/bin/ls", "ls", "-al", "MVEE", NULL);
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
#define REGISTER_PARSEC(num, ver, config, name) case num: { parsec_bench = name; parsec_ver = ver; parsec_config = #config; break; }
		REGISTER_PARSEC(30, 2, "gcc-pthreads", "blackscholes"  );
		REGISTER_PARSEC(31, 2, "gcc-pthreads", "bodytrack"     );
		REGISTER_PARSEC(32, 2, "gcc-pthreads", "canneal"       );
		REGISTER_PARSEC(33, 2, "gcc-pthreads", "dedup"         );
		REGISTER_PARSEC(34, 3, "gcc-pthreads", "facesim"       );
		REGISTER_PARSEC(35, 3, "gcc-pthreads", "ferret"        );
		REGISTER_PARSEC(36, 2, "gcc-pthreads", "fluidanimate"  );
		REGISTER_PARSEC(37, 2, "gcc-openmp"  , "freqmine"      );
		REGISTER_PARSEC(38, 2, "gcc-pthreads", "raytrace"      );
		REGISTER_PARSEC(39, 2, "gcc-pthreads", "streamcluster" );
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
        assert(mvee::demo_args.size() >= 2);

		std::stringstream cmd;
		cmd << mvee::config.mvee_root_path;
		cmd << ((parsec_ver == 2 && !splash_bench) ? 
			mvee::config.mvee_parsec2_path : 
				mvee::config.mvee_parsec3_path);
		
#ifdef MVEE_ALLOW_PERF
        if (mvee::use_perf)
			cmd << "/bin/parsecmgmt-perf";
		else
#endif
			cmd << "/bin/parsecmgmt";

		if (access(cmd.str().c_str(), F_OK) == -1)
		{
			printf("ERROR: Tried to start a PARSEC/SPLASH benchmark but could not find PARSEC management script at:\n   %s\n", cmd.str().c_str());
			return;
		}

		cmd << " -a run -p " << (parsec_bench ? parsec_bench : splash_bench)
			<< " -n " << mvee::demo_args[0] 
			<< " -i " << mvee::demo_args[1] 
			<< " -c " << (parsec_config ? parsec_config : "gcc-pthreads");

		start_variant_indirect(cmd.str().c_str());
    }
    else if (spec_bench)
    {
		std::stringstream cmd, specpath;

		// check if we can find the runme script
		cmd << mvee::config.mvee_root_path
		    << "/MVEE/bin/Release/spec/" 
			<< spec_bench << "/ref/runme.sh";

		if (access(cmd.str().c_str(), F_OK) == -1)
		{
			printf("ERROR: Tried to start a SPEC benchmark but could not find runme script at:\n  %s\n",
				   cmd.str().c_str());
			return;
		}

		// check if SPEC is installed
		specpath << mvee::config.mvee_root_path
				 << mvee::config.mvee_spec2006_path
				 << "/benchspec/";

		if (access(specpath.str().c_str(), F_OK) == -1)
		{
			printf("ERROR: Tried to start a SPEC benchmark but could not find SPEC folder at:\n  %s\n",
				   specpath.str().c_str());
			return;
		}

		// check if the binaries are installed
		specpath << "CPU2006/"
				 << spec_bench
				 << "/build/"
				 << get_spec_profile(native);

		if (access(specpath.str().c_str(), F_OK) == -1)
		{
			printf("ERROR: Tried to start a SPEC benchmark but could not find build folder at:\n  %s\n",
				   specpath.str().c_str());
			return;
		}

		start_variant_indirect(cmd.str().c_str());
    }

    printf("ERROR: the monitor could not start demo %d. Please check if the binary exists...\n", demonum);
}
