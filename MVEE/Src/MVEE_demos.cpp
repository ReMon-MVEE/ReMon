/*
 * GHent University Multi-Variant Execution Environment (GHUMVEE)
 * Copyright (C) 2010-2015 Stijn Volckaert, Ghent University
 *                   <svolckae@elis.ugent.be>
 *                     All rights reserved.
 *
 * This software package is licensed to University of California, Irvine
 * under the terms and conditions found in LICENSE.txt.
 */

/*-----------------------------------------------------------------------------
    Includes
-----------------------------------------------------------------------------*/
#include <stdlib.h>
#include <assert.h>
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

	
	switch(demonum)
	{
		// PARSEC bodytrack
    	case 81:
		// PARSEC fluidanimate
    	case 86:
		// PARSEC raytrace
     	case 88:
        // PARSEC streamcluster
    	case 89:
			mvee::demo_schedule_type = MVEE_CLEVER_SCHEDULING;
			break;

		// PARSEC x264
	    case 92:
			mvee::demo_has_many_threads = true;
			break;
	}

	if (demonum >= 158 && demonum <= 171)
		mvee::demo_schedule_type = MVEE_CLEVER_SCHEDULING;
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


    if ((demonum < 60 || demonum > 72)
        && (demonum < 118 || demonum > 134))
        return;

    if ((demonum >= 60 && demonum <= 72)
        || (demonum >= 118 && demonum <= 134))
    {
        setenv("SPEC",        "/home/stijn/spec2006/spec2006inst",                   1);
        setenv("SPECPATH",    "/home/stijn/spec2006/spec2006inst/benchspec/CPU2006", 1);
        setenv("SPECLIBPATH", "/home/stijn/spec2006/spec2006inst/bin/lib",           1);
//        if (native)
            setenv("SPECPROFILE", SPECPROFILENOPIE, 1);
//        else
//            setenv("SPECPROFILE", SPECPROFILEPIE, 1);
    }
}

/*-----------------------------------------------------------------------------
    start_demo - !!! Most of this stuff is HORRIBLY outdated !!!

    NOTE: This code runs in the replicae processes, not in the monitor!!!
-----------------------------------------------------------------------------*/
void mvee::start_demo(int demonum, int childindex, bool native)
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
        // Hello world app
        case 1:
        {
            execl("../../../ForkTest/a.out", "a.out", NULL);
            break;
        }
        // File hashing test app
        case 2:
        {
            execl("../../../../../../usr/bin/make", "make", "-j", "8", NULL);
            break;
        }
        // Creates a bunch of threads, does some printf'ing and calculates a number...
        // This _SHOULD_ deadlock with the default libc
        // Since there are printfs from different threads, this will also fail with Weak Determinism systems
        case 3:
        {
            execl("../../../TestApp3/TestApp3", "TestApp3", NULL);
            break;
        }
        // The first real killer app => GNOME's calculator.
        case 5:
        {
            //        mvee_mon_add_interposer(MVEE_FILE_GTK_INTERPOSER);
            //        mvee_mon_add_interposer(MVEE_FILE_GLIB_INTERPOSER);
            //        mvee_mon_add_interposer(MVEE_FILE_ORBIT_INTERPOSER);
            //        mvee_mon_add_interposer(MVEE_FILE_PANGO_INTERPOSER);
            execl("/usr/bin/gnome-calculator", "gnome-calculator", NULL);
            break;
        }
        // Spams hello world until you kill it... This app registers a couple of
        // signal handlers. => if you send one of these signals to the app,
        // the monitor should intercept it and deliver it when the variants
        // are synced.
        case 6:
        {
            execl("../../../TestApp6/TestApp6", "TestApp6", NULL);
            break;
        }
        // mmap testing application. Tries to mmap with PROT_READ|PROT_WRITE and MAP_SHARED.
        // This shouldn't be allowed.
        case 7:
        {
            execl("../../../TestApp7/bin/Debug/TestApp", "TestApp", NULL);
            break;
        }
        // Pretty much the same as app 6. No idea why this demois even here
        case 8:
        {
            execl("../../../TestApp8/TestApp8", "TestApp8", NULL);
            break;
        }
        // Socket testing app. Tries to bind a socket.
        case 9:
        {
            execl("../../../TestApp9/TestApp9", "TestApp9", NULL);
            break;
        }
        // Simple I/O Benchmark
        case 10:
        {
            execl("../../../TestApp10/TestApp10", "TestApp10", NULL);
            break;
        }
        // Simple CPU Benchmark
        case 11:
        {
            execl("../../../TestApp11/TestApp11", "TestApp11", NULL);
            break;
        }
        // Simple Memory Benchmark (Sequential Reading)
        case 12:
        {
            execl("../../../TestApp12/TestApp12", "TestApp12", NULL);
            break;
        }
        // Simple Threading Benchmark (Short Lived Threads)
        case 13:
        {
            //mvee_mon_add_interposer(MVEE_FILE_PTHREAD_INTERPOSER);
            execl("../../../TestApp13/TestApp13", "TestApp13", NULL);
            break;
        }
        // Simple Memory Benchmark (Random Reading)
        case 14:
        {
            execl("../../../TestApp12/TestApp12", "TestApp12", "1", NULL);
            break;
        }
        // Simple Threading Benchmark (Long Lived Threads)
        case 15:
        {
            execl("../../../TestApp15/TestApp15", "TestApp15", NULL);
            break;
        }
        // xclock test. This is the most trivial graphical application in the
        // universe. Unlike other graphical applications, this one should run
        // just fine without any interposers...
        case 16:
        {
            execl("/usr/bin/xclock", "xclock", NULL);
            break;
        }
        // Similar to the mmap test. This one uses sysv's ipc interface to
        // attach to shared memory. This is not allowed...
        case 17:
        {
            execl("../../../SHMTest/bin/Debug/SHMTest", "SHMTest", NULL);
            break;
        }
        // simple socket client (requires running server)
        case 18:
        {
            execl("../../../TestApp16/Client/bin/Debug/Client", "Client", NULL);
            break;
        }
        // simple socket server
        case 19:
        {
            execl("../../../TestApp16/Server/bin/Debug/Server", "Server", NULL);
            break;
        }
        // large file read
        case 20:
        {
            execl("../../../LargeRead/bin/Debug/LargeRead", "LargeRead", NULL);
            break;
        }
        // first non-trivial networking application. Running wget inside the
        // MVEE actually revealed a stack overflow bug!
        case 21:
        {
            execl("/usr/bin/wget", "wget", "http://www.google.com", NULL);
            break;
        }
        // Another networking test
        case 22:
        {
            assert(mvee::demo_args.size() >= 2);
            execl("../../../UDPSocket/Client", "Client", mvee::demo_args[0].c_str(), mvee::demo_args[1].c_str(), NULL);
            break;
        }
        // This is a test for our monitor's SEGV handler.
        case 23:
        {
            execl("../../../SignalTest/SignalTest", "SignalTest", NULL);
            break;
        }
        // Very similar to xclock but with some extra I/O.
        // Once again, no interposers needed.
        case 24:
        {
            execl("/usr/bin/xeyes", "xeyes", NULL);
            break;
        }
        // Tests some RDTSC related monitor functions
        case 25:
        {
            execl("../../../RdtscTest/bin/Debug/RdtscTest", "RdtscTest", NULL);
            break;
        }
        // Tests getTID/getPID/... functions
        case 26:
        {
            execl("/home/stijn/MVEE/PIDTIDTest/PIDTIDTest", "PIDTIDTest", NULL);
            break;
        }
        // clock_gettime test
        case 27:
        {
            execl("../../../ClockTest/bin/Debug/ClockTest", "ClockTest", NULL);
            break;
        }
        // O_CREAT | O_EXCL test
        case 28:
        {
            execl("../../../ExclusiveCreateTest/ExclusiveCreateTest", "ExclusiveCreateTest", NULL);
            break;
        }
        // Simple graphical program on the GTK stack
        case 29:
        {
            execl("../../../HelloWorldGTK/bin/Debug/HelloWorldGTK", "HelloWorldGTK", NULL);
            break;
        }
        case 30:
            execl("../../../StatTest/StatTest",                           "StatTest",         "MVEE", NULL);
            break;
        case 31:
            execl("/usr/games/mahjongg",                                  "mahjongg",         NULL);
            break;
        case 32:
            execl("../../../ForkTest/ForkTest",                           "ForkTest",         NULL);
            break;
        case 33:
            execl("../../../ExecTest/bin/Debug/ExecTest",                 "ExecTest",         NULL);
            break;
        case 34:
            execl("../../../CondVarTest/bin/Debug/CondVarTest",           "CondVarTest",      NULL);
            break;
        case 35:
            execl("../../../SocketPairTest/SocketPairTest",               "SocketPairTest",   NULL);
            break;
        case 36:
            execl("../../../FileLockTest/FileLockTest",                   "FileLockTest",     NULL);
            break;
        case 37:
            execl("../../../SetXidTest/bin/Debug/SetXidTest",             "SetXidTest",       NULL);
            break;
        case 38:
            execl("../../../MutexTest/bin/Debug/MutexTest",               "MutexTest",        NULL);
            break;
        case 39:
            execl("../../../NetLinkTest/NetLinkTest",                     "NetLinkTest",      NULL);
            break;
        case 40:
            execl("../../../PollTest/PollTest",                           "PollTest",         NULL);
            break;
        case 42:
            execl("../../../HashingBenchmark/bin/Debug/HashingBenchmark", "HashingBenchmark", NULL);
            break;
        case 54:
            //mvee_mon_add_interposer(MVEE_FILE_PTHREAD_INTERPOSER);
            //mvee_mon_add_interposer(MVEE_FILE_ORBIT_INTERPOSER);
            execl("/usr/bin/kcalc",          "kcalc",        NULL);
            break;
        case 56:
            execl("/usr/games/quadrapassel", "quadrapassel", NULL);
            break;
        case 60:
            execl("/bin/sh",                 "sh",           "./spec/400.perlbench/ref/runme.sh",  NULL);
            break;
        case 61:
            execl("/bin/sh",                 "sh",           "./spec/401.bzip2/ref/runme.sh",      NULL);
            break;
        case 62:
            execl("/bin/sh",                 "sh",           "./spec/403.gcc/ref/runme.sh",        NULL);
            break;
        case 63:
            execl("/bin/sh",                 "sh",           "./spec/429.mcf/ref/runme.sh",        NULL);
            break;
        case 64:
            execl("/bin/sh",                 "sh",           "./spec/445.gobmk/ref/runme.sh",      NULL);
            break;
        case 65:
            execl("/bin/sh",                 "sh",           "./spec/456.hmmer/ref/runme.sh",      NULL);
            break;
        case 66:
            execl("/bin/sh",                 "sh",           "./spec/458.sjeng/ref/runme.sh",      NULL);
            break;
        case 67:
            execl("/bin/sh",                 "sh",           "./spec/462.libquantum/ref/runme.sh", NULL);
            break;
        case 68:
            execl("/bin/sh",                 "sh",           "./spec/464.h264ref/ref/runme.sh",    NULL);
            break;
        case 69:
            execl("/bin/sh",                 "sh",           "./spec/471.omnetpp/ref/runme.sh",    NULL);
            break;
        case 70:
            execl("/bin/sh",                 "sh",           "./spec/473.astar/ref/runme.sh",      NULL);
            break;
        case 71:
            execl("/bin/sh",                 "sh",           "./spec/483.xalancbmk/ref/runme.sh",  NULL);
            break;

        case 73:
            execl("/usr/bin/kate", "kate", NULL);
            break;
        //
        // PARSEC blackscholes benchmark
        //
        case 80:
            parsec_bench  = "blackscholes";
            break;
        //
        // PARSEC bodytrack benchmark
        //
        case 81:
            parsec_bench  = "bodytrack";
            break;
        //
        // PARSEC canneal benchmark
        //
        case 82:
            // parsec_bench = "canneal";
            break;
        //
        // PARSEC dedup benchmark
        //
        case 83:
            parsec_bench  = "dedup";
            break;
        //
        // PARSEC facesim benchmark
        //
        case 84:
            parsec_bench = "facesim";
			parsec_ver = 3;
            break;
        //
        // PARSEC ferret benchmark
        //
        case 85:
            parsec_bench  = "ferret";
			parsec_ver = 3;
            break;
        //
        // PARSEC fluidanimate benchmark
        //
        case 86:
            parsec_bench  = "fluidanimate";
            break;
        //
        // PARSEC freqmine benchmark
        //
        case 87:
            parsec_bench  = "freqmine";
            parsec_config = "gcc-openmp";
            break;
        //
        // PARSEC raytrace benchmark
        //
        case 88:
            parsec_bench  = "raytrace";
            break;
        //
        // PARSEC streamcluster benchmark
        //
        case 89:
            parsec_bench  = "streamcluster";
            break;
        //
        // PARSEC swaptions benchmark
        //
        case 90:
            parsec_bench  = "swaptions";
            break;
        //
        // PARSEC vips benchmark
        //
        case 91:
            parsec_bench  = "vips";
            break;
        //
        // PARSEC x264 benchmark
        //
        case 92:
            parsec_bench  = "x264";
            break;
        case 105:
            //      execl("/usr/bin/mplayer", "mplayer", "-vo", "x11", "-nosound", "/home/stijn/cscw94_10_m2.mpg", NULL);
            execl("/usr/bin/mplayer", "mplayer", "-vo", "x11", "-ao", "null", "-hardframedrop", "/home/stijn/big_buck_bunny_1080p_h264.mov", NULL);
            //execl("/usr/bin/mplayer", "mplayer", "-vo", "x11", "-ao", "null", "-hardframedrop", "/home/stijn/big_buck_bunny_720p_h264.mov", NULL);
            break;
        case 106:
            execl("/usr/bin/vlc",                     "vlc",         "--no-xvideo-shm", "/media/sf_Hostdocs/FF14.mp4", NULL);
            break;
        case 107:
            execl("/usr/bin/javac",                   "javac",       "-version",        NULL);
            break;
        case 108:
            execl("../../../system_test/system_test", "system_test", "ls",              NULL);
            break;
        //
        // RDTSCBenchmark
        //
        case 113:
            execl("/home/stijn/MVEE/RDTSCBenchmark/RDTSCBenchmark", "RDTSCBenchmark", NULL);
            break;
        case 114:
            execl("/home/stijn/MVEE/mmantest/mmantest",             "mmantest",       NULL);
            break;
        case 116:
            execl("/home/stijn/MVEE/miniferret/miniferret",         "miniferret",     NULL);
            break;
        case 117:
            //execl("/bin/tar", "tar", "-xvf", "/home/stijn/parsec-2.1/pkgs/apps/vips/inputs/input_native.tar", NULL);
            execl("/bin/tar", "tar", "-xvf", "/home/stijn/MVEE/MVEE/bin/Debug/logs.tar.gz", NULL);
            break;
        // SPECfp 2006
        case 118:
            execl("/bin/sh",                                                          "sh",                           "./spec/410.bwaves/ref/runme.sh",    NULL);
            break;
        case 119:
            execl("/bin/sh",                                                          "sh",                           "./spec/416.gamess/ref/runme.sh",    NULL);
            break;
        case 120:
            execl("/bin/sh",                                                          "sh",                           "./spec/433.milc/ref/runme.sh",      NULL);
            break;
        case 121:
            execl("/bin/sh",                                                          "sh",                           "./spec/434.zeusmp/ref/runme.sh",    NULL);
            break;
        case 122:
            execl("/bin/sh",                                                          "sh",                           "./spec/435.gromacs/ref/runme.sh",   NULL);
            break;
        case 123:
            execl("/bin/sh",                                                          "sh",                           "./spec/436.cactusADM/ref/runme.sh", NULL);
            break;
        case 124:
            execl("/bin/sh",                                                          "sh",                           "./spec/437.leslie3d/ref/runme.sh",  NULL);
            break;
        case 125:
            execl("/bin/sh",                                                          "sh",                           "./spec/444.namd/ref/runme.sh",      NULL);
            break;
        case 126:
            execl("/bin/sh",                                                          "sh",                           "./spec/447.dealII/ref/runme.sh",    NULL);
            break;
        case 127:
            execl("/bin/sh",                                                          "sh",                           "./spec/450.soplex/ref/runme.sh",    NULL);
            break;
        case 128:
            execl("/bin/sh",                                                          "sh",                           "./spec/453.povray/ref/runme.sh",    NULL);
            break;
        case 129:
            execl("/bin/sh",                                                          "sh",                           "./spec/454.calculix/ref/runme.sh",  NULL);
            break;
        case 130:
            execl("/bin/sh",                                                          "sh",                           "./spec/459.GemsFDTD/ref/runme.sh",  NULL);
            break;
        case 131:
            execl("/bin/sh",                                                          "sh",                           "./spec/465.tonto/ref/runme.sh",     NULL);
            break;
        case 132:
            execl("/bin/sh",                                                          "sh",                           "./spec/470.lbm/ref/runme.sh",       NULL);
            break;
        case 133:
            execl("/bin/sh",                                                          "sh",                           "./spec/481.wrf/ref/runme.sh",       NULL);
            break;
        case 134:
            execl("/bin/sh",                                                          "sh",                           "./spec/482.sphinx3/ref/runme.sh",   NULL);
            break;
        case 135:
            execl("/home/stijn/buffertest",                                           "buffertest",                   NULL);
            break;
        case 136:
            execl("/home/stijn/MVEE/gettimeofdaytest/gettimeofdaytest",               "gettimeofdaytest",             NULL);
            break;
        case 137:
            execl("/usr/lib/ccache/gcc",                                              "gcc",                          "--version", NULL);
            break;
        case 141:
            execl("/usr/local/nginx/sbin/nginx",                                      "nginx",                        NULL);
            break;
        case 142:
            execl("/home/stijn/MVEE/getpidtest/getpidtest",                           "getpidtest",                   NULL);
            break;
        case 143:
            execl("/home/stijn/openssl-1.0.1e/apps/openssl",                          "openssl",                      "s_server", "-cert",                                        "server.crt", "-key", "server.key", "-accept", "443", "-www", NULL);
            break;
        case 144:
            execl("/usr/local/sbin/proftpd",                                          "proftpd",                      "-c",       "/home/stijn/MVEE/exploits/proftpd/basic.conf", "-d",         "10",   NULL);
            break;
        case 145:
            execl("/home/stijn/MVEE/syscall_stresstest/syscall_stresstest_1_thread",  "syscall_stresstest_1_thread",  NULL);
            break;
        case 146:
            execl("/home/stijn/MVEE/syscall_stresstest/syscall_stresstest_2_threads", "syscall_stresstest_2_threads", NULL);
            break;
        case 147:
            execl("/home/stijn/MVEE/syscall_stresstest/syscall_stresstest_4_threads", "syscall_stresstest_4_threads", NULL);
            break;
        case 148:
            execl("/home/stijn/MVEE/exploits/mcrypt/installs/bin/mcrypt",             "mcrypt",                       "-d", NULL);
            break;
        case 149:
            execl("/home/stijn/MVEE/ptrace_bug/ptrace_bug",                           "ptrace_bug",                   NULL);
            break;
        case 150:
            execl("/home/stijn/MVEE/i_like_pie/i_like_pie",                           "i_like_pie",                   NULL);
            break;
        case 151:
            //      execl("/usr/local/bin/http-master", "http-master", NULL);
            execl("/home/stijn/.nvm/v0.11.14/bin/node", "node", "/home/stijn/node-test/https-test.js", NULL);
            break;
        case 152:
            execl("/bin/sh",                            "sh",   "/etc/init.d/torque-server",           "start",            NULL);
            break;
        case 153:
            execl("/bin/sh",                            "sh",   "/etc/init.d/torque-server",           "stop",             NULL);
            break;
        case 154:
            execl("/bin/sh",                            "sh",   "-c",                                  "/usr/bin/firefox", NULL);
            break;
        //
        // PARSEC dedup benchmark
        //
        case 155:
            parsec_bench = "deduputcb";
            break;
        case 156:
            execl("/usr/bin/id", "id", NULL);
            break;
        case 157:
            execl("/bin/sh",     "sh", "-c", "/bin/ls", NULL);
            break;

        case 158:
            splash_bench = "splash2x.barnes";
            break;
        case 159:
            splash_bench = "splash2x.cholesky";
            break;
        case 160:
            splash_bench = "splash2x.fft";
            break;
        case 161:
            splash_bench = "splash2x.fmm";
            break;
        case 162:
            splash_bench = "splash2x.lu_cb";
            break;
        case 163:
            splash_bench = "splash2x.lu_ncb";
            break;
        case 164:
            splash_bench = "splash2x.ocean_cp";
            break;
        case 165:
            splash_bench = "splash2x.ocean_ncp";
            break;
        case 166:
            splash_bench = "splash2x.radiosity";
            break;
        case 167:
            splash_bench = "splash2x.radix";
            break;
        case 168:
            splash_bench = "splash2x.raytrace";
            break;
        case 169:
            splash_bench = "splash2x.volrend";
            break;
        case 170:
            splash_bench = "splash2x.water_nsquared";
            break;
        case 171:
            splash_bench = "splash2x.water_spatial";
            break;
        case 172:
            execl("/usr/bin/ruby", "ruby", "--version", NULL);
            break;
	case 173:
		execl("/home/stijn/MVEE/ipmontest/ipmontest", "ipmontest", "5", NULL);
		break;
	case 174:
		execl("/home/stijn/MVEE/ipmontest/ipmontest", "ipmontest", "6", NULL);
		break;

    }

    if (parsec_bench)
    {
        assert(mvee::demo_args.size() >= 2);
#ifdef MVEE_ALLOW_PERF
        if (mvee::use_perf)
        {
            execl("/bin/bash", "bash",
                  "/home/stijn/parsec-2.1/bin/parsecmgmt-perf",
                  "-a", "run", "-p", parsec_bench, "-i", mvee::demo_args[1].c_str(), "-n", mvee::demo_args[0].c_str(), "-c", parsec_config ? parsec_config : "gcc", NULL);
        }
        else
#endif
		if (parsec_ver == 2)
		{
            execl("/bin/bash", "bash",
                  "/home/stijn/parsec-2.1/bin/parsecmgmt",
                  "-a", "run", "-p", parsec_bench, "-i", mvee::demo_args[1].c_str(), "-n", mvee::demo_args[0].c_str(), "-c", parsec_config ? parsec_config : "gcc", NULL);
        }
		else
		{
            execl("/bin/bash", "bash",
                  "/home/stijn/parsec-3.0/bin/parsecmgmt",
                  "-a", "run", "-p", parsec_bench, "-i", mvee::demo_args[1].c_str(), "-n", mvee::demo_args[0].c_str(), "-c", parsec_config ? parsec_config : "gcc-pthreads", NULL);
		}
    }
    else if (splash_bench)
    {
        execl("/bin/bash", "bash",
              "/home/stijn/parsec-3.0/bin/parsecmgmt",
              "-a", "run", "-p", splash_bench, "-i", mvee::demo_args[1].c_str(), "-n", mvee::demo_args[0].c_str(), "-c", "gcc-pthreads", NULL);
    }
    else if (spec_bench)
    {
        const char* config = native ? SPECCONFIGNOPIE : SPECCONFIGPIE;
        execl("/home/stijn/spec2006/spec2006inst/bin/specperl", "specperl",
              "-I", "/home/stijn/spec2006/spec2006inst/bin",
              "-I", "/home/stijn/spec2006/spec2006inst/bin/lib",
              "/home/stijn/spec2006/spec2006inst/bin/runspec", "--action=run", "-c", config, "-n", "1", "--loose", "--input", "ref", spec_bench, NULL);
    }


    printf("ERROR: the monitor could not start demo %d. Please check if the binary exists...\n", demonum);
//    printf("ERROR: if you're running with MVEE_HIDE_VDSO or MVEE_FORCE_DISJOINT_CODE, this\n");
//    printf("ERROR: might be caused by not having a valid MVEE_LD_Loader!\n");
//    printf("ERROR: Compile one for your architecture by running the comp.sh script in MVEE/MVEE_LD_Loader\n");
}
