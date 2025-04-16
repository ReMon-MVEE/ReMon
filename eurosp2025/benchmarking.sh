#!/bin/bash


__allocator="pmvee"
__kernel_module="skip"
__execute_pre=""

__orig_remon_dir="##fortdivide_location##/"
__orig_remon_exec_dir="$__orig_remon_dir/MVEE/bin/Release/"

__remon_dir="##fortdivide_location##/"
__remon_exec_dir="##fortdivide_location##/MVEE/bin/Release/"
__remon_glibc_dir="##fortdivide_location##/eurosp2025/ReMon-glibc/"
__benchmark_dir="##fortdivide_location##/eurosp2025/"
__benchmark_dir_out="$__benchmark_dir/out/"

__server_ip="localhost:8080"

__pmvee_ld_preload="LD_PRELOAD=##fortdivide_location##/PMVEE/allocator/pmvee_allocator.so"

__sub_output_dir=$(date +"%Y-%m-%d-%T")
__today_output_dir=$(date +"%Y-%m-%d")
__output_dir_base="./paper-outputs/"

__log="/tmp/pmvee-benchmarking-last.log"

__connections=10


# __index_sizes=( "" "-8" "-16" "-32" "-64" )
__index_sizes=("")


function logf
{
    echo " [$(date +"%Y-%m-%d %T")] > $1"
    echo " [$(date +"%Y-%m-%d %T")] > $1" >> $__log
}


function execute_and_continue
{
    ssh -t fortdivide-benchmark "$1" &
}


function execute_and_wait
{
    ssh -t fortdivide-benchmark $1
}


function execute_and_log
{
    ssh -t fortdivide-benchmark $1
}


function benchmark_on
{
    ssh -t fortdivide-benchmark "for __cpu_freq in /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor; do [ -f \$__cpu_freq ] || continue; echo -n "performance" | sudo tee \$__cpu_freq > /dev/null || true; done; echo -n "1" | sudo tee "/sys/devices/system/cpu/intel_pstate/no_turbo" > /dev/null; echo -n "off" | sudo tee "/sys/devices/system/cpu/smt/control" > /dev/null; echo -n "Y" | sudo tee /sys/module/kernel/parameters/ignore_rlimit_data; sudo sysctl -w kernel.yama.ptrace_scope=0"
}


function benchmark_off
{
    ssh -t fortdivide-benchmark "echo -n "0" | sudo tee "/sys/devices/system/cpu/intel_pstate/no_turbo" > /dev/null; echo -n "on"  | sudo tee "/sys/devices/system/cpu/smt/control" > /dev/null; for __cpu_freq in /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor; do [ -f \$__cpu_freq ] || continue; echo -n "powersave" | sudo tee \$__cpu_freq > /dev/null || true; done; echo -n "N" | sudo tee /sys/module/kernel/parameters/ignore_rlimit_data"
}


function kill_all
{
    execute_and_wait "killall mvee nginx lighttpd"
}


function benchmark_server
{
    for i in {1..10}
    do
        sleep 1
        wrk -t 1 -c $__connections --timeout 30 -d 10 "http://$__server_ip/index$2.html" >> "$1" && break
        logf "going to sleep and retrying in a bit."
    done
}


function nginx-base
{
    for __index in "${__index_sizes[@]}"
    do
        __output_file="$2$__index"
        echo "" > $__output_file
        logf "$__output_file"
        for i in {1..5}
        do
            logf "starting server ($1)"
            execute_and_continue "$__ld_preload $1 >> $__log"
            benchmark_server "$__output_file" "$__index"
            execute_and_wait "$1 -s stop"
        done
        grep -nr "Req/Sec" $__output_file
    done
    logf "===========================================================\n"
}


function server-bench-base
{
    ssh -t fortdivide-benchmark $__remon_dir/eurosp2025/fortdivide-libc.sh
    for __index in "${__index_sizes[@]}"
    do
        __output_file="$2$__index"
        echo "" > "$__output_file"
        logf "$__output_file"
        for __i in {1..5}
        do
            logf "starting server ($1)"
            execute_and_continue "$__ld_preload $1 >> $__log" 
            benchmark_server "$__output_file" "$__index"
            logf killing server
            kill_all
        done
        grep -nr "Req/Sec" $__output_file
    done
    logf "===========================================================\n"
}


function server-bench
{
    ssh -t fortdivide-benchmark $__remon_dir/eurosp2025/fortdivide-libc.sh
    for __index in "${__index_sizes[@]}"
    do
        __output_file="$2$__index"
        echo "" > "$__output_file"
        logf "$__output_file"
        for __i in {1..5}
        do
            logf "MVEE starting server ($1)"
            execute_and_continue "cd $__remon_exec_dir && ./mvee -- $__ld_preload $1"
            benchmark_server "$__output_file" "$__index"
            kill_all
        done
        grep -nr "Req/Sec" $__output_file
    done
    logf "===========================================================\n"
}


function orig-server-bench
{
    ssh -t fortdivide-benchmark $__orig_remon_dir/scripts/switch_patched_binaries.sh ubuntu20
    for __index in "${__index_sizes[@]}"
    do
        __output_file="$2$__index"
        echo "" > "$__output_file"
        logf "$__output_file"
        for __i in {1..5}
        do
            logf "original MVEE starting server ($1)"
            execute_and_continue "cd $__orig_remon_exec_dir && ./mvee -- $__ld_preload $1"
            benchmark_server "$__output_file" "$__index"
            kill_all
        done
        grep -nr "Req/Sec" $__output_file
    done
    logf "===========================================================\n"
}


function nginx-scan-benchmark
{
    __output_dir="$__output_dir_base/$__sub_output_dir/$__kernel_module/$__allocator/"
    mkdir -p "$__output_dir/$__connections-connections" || true

    logf "building nginx binaries with heap scanning ($1)"
    execute_and_wait "cd $__benchmark_dir/nginx-1.23.3/ && ./nginx-1.23.3-build.sh $1 --pmvee-single-scanning --mappings-single-scanning --base 1>/dev/null"
    execute_and_wait "cd $__remon_dir/PMVEE && make lib-scanning 1>/dev/null"
    execute_and_wait "ln -fs $__orig_remon_dir/IP-MON/libipmon-nginx.so $__orig_remon_dir/IP-MON/libipmon.so"

    logf "Outputting to $__output_dir"

    logf "Running nginx with $3 workers"
    execute_and_wait "sed -i 's/worker_processes.*/worker_processes $3;/g' $__benchmark_dir/nginx-1.23.3/conf/nginx.conf"

    __ld_preload=$__pmvee_ld_preload
    nginx-base   "$__benchmark_dir_out/nginx-1.23.3/base/sbin/nginx" "$__output_dir/$__connections-connections/nginx$2-scan-$3-baseline"

    __ld_preload=""
    execute_and_wait "sed -i 's/\"use_ipmon\" : 1/\"use_ipmon\" : 0/g' $__remon_exec_dir/MVEE.ini"
    execute_and_wait "sed -i 's/\"use_ipmon\" : 1/\"use_ipmon\" : 0/g' $__orig_remon_exec_dir/MVEE.ini"
    execute_and_wait "ln -fs $__orig_remon_dir/IP-MON/libipmon-nginx.so $__orig_remon_dir/IP-MON/libipmon.so"
    orig-server-bench "$__benchmark_dir_out/nginx-1.23.3/base/sbin/nginx" "$__output_dir/$__connections-connections/nginx$2-scan-$3-remon-noipmon"
    execute_and_wait "ln -fs $__orig_remon_dir/IP-MON/libipmon-pmvee.so $__orig_remon_dir/IP-MON/libipmon.so"
    server-bench "$__benchmark_dir_out/nginx-1.23.3/pmvee/single/sbin/nginx" "$__output_dir/$__connections-connections/nginx$2-scan-$3-pmvee-noipmon"

    __ld_preload=""
    execute_and_wait "sed -i 's/\"use_ipmon\" : 0/\"use_ipmon\" : 1/g' $__remon_exec_dir/MVEE.ini"
    execute_and_wait "sed -i 's/\"use_ipmon\" : 0/\"use_ipmon\" : 1/g' $__orig_remon_exec_dir/MVEE.ini"
    execute_and_wait "ln -fs $__orig_remon_dir/IP-MON/libipmon-nginx.so $__orig_remon_dir/IP-MON/libipmon.so"
    orig-server-bench "$__benchmark_dir_out/nginx-1.23.3/base/sbin/nginx" "$__output_dir/$__connections-connections/nginx$2-scan-$3-remon-withipmon"
    execute_and_wait "ln -fs $__orig_remon_dir/IP-MON/libipmon-pmvee.so $__orig_remon_dir/IP-MON/libipmon.so"
    server-bench "$__benchmark_dir_out/nginx-1.23.3/pmvee/single/sbin/nginx" "$__output_dir/$__connections-connections/nginx$2-scan-$3-pmvee-withipmon"

    execute_and_wait "cd $__benchmark_dir/nginx-1.23.3/ && ./nginx-1.23.3-build.sh $1 --ngx-split --pmvee-extra --mappings-single 1>/dev/null"
    execute_and_wait "cd $__remon_dir/PMVEE && make lib 1>/dev/null"

    execute_and_wait "ln -fs $__orig_remon_dir/IP-MON/libipmon-pmvee.so $__orig_remon_dir/IP-MON/libipmon.so"
    __ld_preload=""
    execute_and_wait "sed -i 's/\"use_ipmon\" : 1/\"use_ipmon\" : 0/g' $__remon_exec_dir/MVEE.ini"
    server-bench "$__benchmark_dir_out/nginx-1.23.3/pmvee/single/sbin/nginx" "$__output_dir/$__connections-connections/nginx-emulate$2-$3-pmvee-noipmon"

    __ld_preload=""
    execute_and_wait "sed -i 's/\"use_ipmon\" : 0/\"use_ipmon\" : 1/g' $__remon_exec_dir/MVEE.ini"
    server-bench "$__benchmark_dir_out/nginx-1.23.3/pmvee/single/sbin/nginx" "$__output_dir/$__connections-connections/nginx-emulate$2-$3-pmvee-withipmon"

    execute_and_wait "cd $__remon_dir/PMVEE && make lib 1>/dev/null"
}


function nginx-diffed-benchmark
{
    __output_dir="$__output_dir_base/$__sub_output_dir/$__kernel_module/$__allocator/"
    mkdir -p "$__output_dir/$__connections-connections" || true

    logf "building nginx binaries with diffed handling ($1)"
    execute_and_wait "cd $__benchmark_dir/nginx-1.23.3/ && ./nginx-1.23.3-build.sh $1 --ngx-split --pmvee-single --mappings-single  --base 1>/dev/null"
    execute_and_wait "cd $__remon_dir/PMVEE && make lib 1>/dev/null"

    logf "Outputting to $__output_dir"

    logf "Running nginx with $3 workers"
    execute_and_wait "sed -i 's/worker_processes.*/worker_processes $3;/g' $__benchmark_dir/nginx-1.23.3/conf/nginx.conf"

    __ld_preload=$__pmvee_ld_preload
    nginx-base   "$__benchmark_dir_out/nginx-1.23.3/base/sbin/nginx" "$__output_dir/$__connections-connections/nginx$2-diffed-$3-baseline"

    __ld_preload=""
    execute_and_wait "sed -i 's/\"use_ipmon\" : 1/\"use_ipmon\" : 0/g' $__remon_exec_dir/MVEE.ini"
    execute_and_wait "sed -i 's/\"use_ipmon\" : 1/\"use_ipmon\" : 0/g' $__orig_remon_exec_dir/MVEE.ini"
    execute_and_wait "ln -fs $__orig_remon_dir/IP-MON/libipmon-nginx.so $__orig_remon_dir/IP-MON/libipmon.so"
    orig-server-bench "$__benchmark_dir_out/nginx-1.23.3/base/sbin/nginx" "$__output_dir/$__connections-connections/nginx$2-diffed-$3-remon-noipmon"
    execute_and_wait "ln -fs $__orig_remon_dir/IP-MON/libipmon-pmvee.so $__orig_remon_dir/IP-MON/libipmon.so"
    server-bench "$__benchmark_dir_out/nginx-1.23.3/pmvee/single/sbin/nginx" "$__output_dir/$__connections-connections/nginx$2-diffed-$3-pmvee-noipmon"

    __ld_preload=""
    execute_and_wait "sed -i 's/\"use_ipmon\" : 0/\"use_ipmon\" : 1/g' $__remon_exec_dir/MVEE.ini"
    execute_and_wait "sed -i 's/\"use_ipmon\" : 0/\"use_ipmon\" : 1/g' $__orig_remon_exec_dir/MVEE.ini"
    execute_and_wait "ln -fs $__orig_remon_dir/IP-MON/libipmon-nginx.so $__orig_remon_dir/IP-MON/libipmon.so"
    orig-server-bench "$__benchmark_dir_out/nginx-1.23.3/base/sbin/nginx" "$__output_dir/$__connections-connections/nginx$2-diffed-$3-remon-withipmon"
    execute_and_wait "ln -fs $__orig_remon_dir/IP-MON/libipmon-pmvee.so $__orig_remon_dir/IP-MON/libipmon.so"
    server-bench "$__benchmark_dir_out/nginx-1.23.3/pmvee/single/sbin/nginx" "$__output_dir/$__connections-connections/nginx$2-diffed-$3-pmvee-withipmon"
}


function nginx-benchmark
{
    __output_dir="$__output_dir_base/$__sub_output_dir/$__kernel_module/$__allocator/"
    mkdir -p "$__output_dir/$__connections-connections" || true

    logf "building nginx binaries ($1)"
    execute_and_wait "cd $__benchmark_dir/nginx-1.23.3/ && ./nginx-1.23.3-build.sh $1 --pmvee-stubs --pmvee --mappings --base 1>/dev/null"
    execute_and_wait "cd $__remon_dir/PMVEE && make lib 1>/dev/null"

    logf "Outputting to $__output_dir"

    logf "Running nginx with $3 workers"
    execute_and_wait "sed -i 's/worker_processes.*/worker_processes $3;/g' $__benchmark_dir/nginx-1.23.3/conf/nginx.conf"

    __ld_preload=$__pmvee_ld_preload
    nginx-base   "$__benchmark_dir_out/nginx-1.23.3/base/sbin/nginx" "$__output_dir/$__connections-connections/nginx$2-$3-baseline"

    __ld_preload=""
    execute_and_wait "sed -i 's/\"use_ipmon\" : 1/\"use_ipmon\" : 0/g' $__remon_exec_dir/MVEE.ini"
    execute_and_wait "sed -i 's/\"use_ipmon\" : true/\"use_ipmon\" : false/g' $__orig_remon_exec_dir/MVEE.ini"
    execute_and_wait "ln -fs $__orig_remon_dir/IP-MON/libipmon-nginx.so $__orig_remon_dir/IP-MON/libipmon.so"
    server-bench "$__benchmark_dir_out/nginx-1.23.3/base/sbin/nginx" "$__output_dir/$__connections-connections/nginx$2-$3-remon-noipmon"
    execute_and_wait "ln -fs $__orig_remon_dir/IP-MON/libipmon-pmvee.so $__orig_remon_dir/IP-MON/libipmon.so"
    server-bench "$__benchmark_dir_out/nginx-1.23.3/pmvee/leader/sbin/nginx" "$__output_dir/$__connections-connections/nginx$2-$3-pmvee-noipmon"

    __ld_preload=""
    execute_and_wait "sed -i 's/\"use_ipmon\" : 0/\"use_ipmon\" : 1/g' $__remon_exec_dir/MVEE.ini"
    execute_and_wait "sed -i 's/\"use_ipmon\" : false/\"use_ipmon\" : true/g' $__orig_remon_exec_dir/MVEE.ini"
    execute_and_wait "ln -fs $__orig_remon_dir/IP-MON/libipmon-nginx.so $__orig_remon_dir/IP-MON/libipmon.so"
    server-bench "$__benchmark_dir_out/nginx-1.23.3/base/sbin/nginx" "$__output_dir/$__connections-connections/nginx$2-$3-remon-withipmon"
    execute_and_wait "ln -fs $__orig_remon_dir/IP-MON/libipmon-pmvee.so $__orig_remon_dir/IP-MON/libipmon.so"
    server-bench "$__benchmark_dir_out/nginx-1.23.3/pmvee/leader/sbin/nginx" "$__output_dir/$__connections-connections/nginx$2-$3-pmvee-withipmon"
}


function lighttpd-benchmark
{
    execute_and_wait "cd $__remon_dir/build && make enable-ipmon-pmvee && make benchmark && make -j 1>/dev/null"

    logf "building lighttpd binaries ($1)"
    execute_and_wait "cd $__benchmark_dir/lighttpd-1.4.60 && ./lighttpd-1.4.60-build.sh --base $1 --pmvee --mappings 1>/dev/null"
    execute_and_wait "cd $__remon_dir/PMVEE && make lib 1>/dev/null"
    __output_dir="$__output_dir_base/$__sub_output_dir/$__kernel_module/$__allocator/"
    mkdir -p "$__output_dir/$__connections-connections" || true
    logf "Outputting to $__output_dir"

    __ld_preload=$__pmvee_ld_preload
    server-bench-base "$__benchmark_dir_out/lighttpd-1.4.60/base/sbin/lighttpd -D -f $__benchmark_dir_out/lighttpd-1.4.60/base/conf/test.conf" "$__output_dir/$__connections-connections/lighttpd$2-baseline"

    __ld_preload=""
    execute_and_wait "sed -i 's/\"use_ipmon\" : 1/\"use_ipmon\" : 0/g' $__remon_exec_dir/MVEE.ini"
    execute_and_wait "sed -i 's/\"use_ipmon\" : true/\"use_ipmon\" : false/g' $__orig_remon_exec_dir/MVEE.ini"
    execute_and_wait "ln -fs $__orig_remon_dir/IP-MON/libipmon-default.so  $__orig_remon_dir/IP-MON/libipmon.so"
    orig-server-bench "\"$__benchmark_dir_out/lighttpd-1.4.60/base/sbin/lighttpd -D -f $__benchmark_dir_out/lighttpd-1.4.60/base/conf/test.conf\"" "$__output_dir/$__connections-connections/lighttpd$2-remon-noipmon"
    execute_and_wait "ln -fs $__orig_remon_dir/IP-MON/libipmon-pmvee.so  $__orig_remon_dir/IP-MON/libipmon.so"
    server-bench "\"$__benchmark_dir_out/lighttpd-1.4.60/pmvee/leader/sbin/lighttpd -D -f $__benchmark_dir_out/lighttpd-1.4.60/base/conf/test.conf\"" "$__output_dir/$__connections-connections/lighttpd$2-pmvee-noipmon"

    __ld_preload=""
    execute_and_wait "sed -i 's/\"use_ipmon\" : 0/\"use_ipmon\" : 1/g' $__remon_exec_dir/MVEE.ini"
    execute_and_wait "sed -i 's/\"use_ipmon\" : false/\"use_ipmon\" : true/g' $__orig_remon_exec_dir/MVEE.ini"
    execute_and_wait "ln -fs $__orig_remon_dir/IP-MON/libipmon-default.so  $__orig_remon_dir/IP-MON/libipmon.so"
    orig-server-bench "\"$__benchmark_dir_out/lighttpd-1.4.60/base/sbin/lighttpd -D -f $__benchmark_dir_out/lighttpd-1.4.60/base/conf/test.conf\"" "$__output_dir/$__connections-connections/lighttpd$2-remon-withipmon"
    execute_and_wait "ln -fs $__orig_remon_dir/IP-MON/libipmon-pmvee.so  $__orig_remon_dir/IP-MON/libipmon.so"
    server-bench "\"$__benchmark_dir_out/lighttpd-1.4.60/pmvee/leader/sbin/lighttpd -D -f $__benchmark_dir_out/lighttpd-1.4.60/base/conf/test.conf\"" "$__output_dir/$__connections-connections/lighttpd$2-pmvee-withipmon"
}


function mapping-count-benchmark
{
    __output_dir="$__output_dir_base/$__sub_output_dir/$__kernel_module/$__allocator/mapping_count/"
    mkdir -p "$__output_dir" || true

    logf "building mapping count binaries"
    execute_and_wait "cd $__benchmark_dir/microbenchmarks/mapping_count && make 1>/dev/null"

    execute_and_wait "cd $__remon_dir/build && make benchmark && make enable-ipmon-pmvee && make -j 1>/dev/null"


    logf "Outputting to $__output_dir"

    execute_and_wait "echo "" > /tmp/pmvee_temp_log_copy_later"
    for i in {1..5}
    do
        execute_and_wait "cd $__benchmark_dir/microbenchmarks/mapping_count/bin/ && ./mapping_count_native >> /tmp/pmvee_temp_log_copy_later"
    done
    scp fortdivide-benchmark:/tmp/pmvee_temp_log_copy_later $__output_dir/native

    execute_and_wait "echo "" > /tmp/pmvee_temp_log_copy_later"
    for i in {1..5}
    do
        execute_and_wait "cd $__benchmark_dir/microbenchmarks/mapping_count/bin/ && ./mapping_count_native_sync >> /tmp/pmvee_temp_log_copy_later"
    done
    scp fortdivide-benchmark:/tmp/pmvee_temp_log_copy_later $__output_dir/native_sync

    ssh -t fortdivide-benchmark $__remon_dir/eurosp2025/fortdivide-libc.sh

    execute_and_wait "sed -i 's/\"use_ipmon\" : 1/\"use_ipmon\" : 0/g' $__remon_exec_dir/MVEE.ini"
    execute_and_wait "sed -i 's/\"use_ipmon\" : 1/\"use_ipmon\" : 0/g' $__orig_remon_exec_dir/MVEE.ini"
    execute_and_wait "echo "" > /tmp/pmvee_temp_log_copy_later"
    for i in {1..5}
    do
        execute_and_wait "cd $__remon_exec_dir && ./mvee -- $__benchmark_dir/microbenchmarks/mapping_count/bin/mapping_count_pmvee >> /tmp/pmvee_temp_log_copy_later"
    done
    scp fortdivide-benchmark:/tmp/pmvee_temp_log_copy_later $__output_dir/pmvee

    execute_and_wait "sed -i 's/\"use_ipmon\" : 0/\"use_ipmon\" : 1/g' $__remon_exec_dir/MVEE.ini"
    execute_and_wait "sed -i 's/\"use_ipmon\" : 0/\"use_ipmon\" : 1/g' $__orig_remon_exec_dir/MVEE.ini"
    execute_and_wait "echo "" > /tmp/pmvee_temp_log_copy_later"
    for i in {1..5}
    do
        execute_and_wait "cd $__remon_exec_dir && ./mvee -- $__benchmark_dir/microbenchmarks/mapping_count/bin/mapping_count_pmvee >> /tmp/pmvee_temp_log_copy_later"
    done
    scp fortdivide-benchmark:/tmp/pmvee_temp_log_copy_later $__output_dir/pmvee-ipmon
}


function switcheroo-benchmark
{
    __output_dir="$__output_dir_base/$__sub_output_dir/$__kernel_module/$__allocator/switcheroo/"
    mkdir -p "$__output_dir" || true

    logf "building switcheroo binaries"
    execute_and_wait "cd $__benchmark_dir/microbenchmarks/switching && make 1>/dev/null"

    execute_and_wait "cd $__remon_dir/build && make benchmark && make enable-ipmon-pmvee && make -j 1>/dev/null"


    logf "Outputting to $__output_dir"

    execute_and_wait "echo "" > /tmp/pmvee_temp_log_copy_later"
    for i in {1..5}
    do
        execute_and_wait "cd $__benchmark_dir/microbenchmarks/switching/bin/ && ./switcheroo_native >> /tmp/pmvee_temp_log_copy_later"
    done
    scp fortdivide-benchmark:/tmp/pmvee_temp_log_copy_later $__output_dir/native

    ssh -t fortdivide-benchmark $__remon_dir/eurosp2025/fortdivide-libc.sh

    execute_and_wait "sed -i 's/\"use_ipmon\" : 1/\"use_ipmon\" : 0/g' $__remon_exec_dir/MVEE.ini"
    execute_and_wait "sed -i 's/\"use_ipmon\" : 1/\"use_ipmon\" : 0/g' $__orig_remon_exec_dir/MVEE.ini"
    execute_and_wait "echo "" > /tmp/pmvee_temp_log_copy_later"
    for i in {1..5}
    do
        execute_and_wait "cd $__remon_exec_dir && ./mvee -- $__benchmark_dir/microbenchmarks/switching/bin/switcheroo_pmvee >> /tmp/pmvee_temp_log_copy_later"
    done
    scp fortdivide-benchmark:/tmp/pmvee_temp_log_copy_later $__output_dir/pmvee

    execute_and_wait "sed -i 's/\"use_ipmon\" : 0/\"use_ipmon\" : 1/g' $__remon_exec_dir/MVEE.ini"
    execute_and_wait "sed -i 's/\"use_ipmon\" : 0/\"use_ipmon\" : 1/g' $__orig_remon_exec_dir/MVEE.ini"
    execute_and_wait "echo "" > /tmp/pmvee_temp_log_copy_later"
    for i in {1..5}
    do
        execute_and_wait "cd $__remon_exec_dir && ./mvee -- $__benchmark_dir/microbenchmarks/switching/bin/switcheroo_pmvee >> /tmp/pmvee_temp_log_copy_later"
    done
    scp fortdivide-benchmark:/tmp/pmvee_temp_log_copy_later $__output_dir/pmvee-ipmon
}


function server-micro-benchmark
{
    __output_dir="$__output_dir_base/$__sub_output_dir/$__kernel_module/$__allocator/server_micro/"
    mkdir -p "$__output_dir" || true

    logf "building server_micro binaries"
    execute_and_wait "cd $__benchmark_dir/microbenchmarks/server_micro && make 1>/dev/null"

    execute_and_wait "cd $__remon_dir/build && make benchmark && make enable-ipmon-pmvee && make -j 1>/dev/null"


    logf "Outputting to $__output_dir"

    execute_and_wait "sed -i 's/\"use_ipmon\" : 1/\"use_ipmon\" : 0/g' $__remon_exec_dir/MVEE.ini"
    execute_and_wait "sed -i 's/\"use_ipmon\" : 1/\"use_ipmon\" : 0/g' $__orig_remon_exec_dir/MVEE.ini"
    execute_and_wait "echo "" > /tmp/pmvee_temp_log_copy_later"
    for i in {1..5}
    do
        execute_and_wait "cd $__remon_exec_dir && ./mvee -- $__benchmark_dir/microbenchmarks/server_micro/bin/server_micro >> /tmp/pmvee_temp_log_copy_later"
    done
    scp fortdivide-benchmark:/tmp/pmvee_temp_log_copy_later $__output_dir/pmvee

    execute_and_wait "sed -i 's/\"use_ipmon\" : 0/\"use_ipmon\" : 1/g' $__remon_exec_dir/MVEE.ini"
    execute_and_wait "sed -i 's/\"use_ipmon\" : 0/\"use_ipmon\" : 1/g' $__orig_remon_exec_dir/MVEE.ini"
    execute_and_wait "echo "" > /tmp/pmvee_temp_log_copy_later"
    for i in {1..5}
    do
        execute_and_wait "cd $__remon_exec_dir && ./mvee -- $__benchmark_dir/microbenchmarks/server_micro/bin/server_micro >> /tmp/pmvee_temp_log_copy_later"
    done
    scp fortdivide-benchmark:/tmp/pmvee_temp_log_copy_later $__output_dir/pmvee-ipmon
}



function set_pmvee_allocator
{
    execute_and_wait "cd $__remon_dir/PMVEE/allocator/ && make -B all"
    __pmvee_ld_preload="LD_PRELOAD=$__remon_dir/PMVEE/allocator/pmvee_allocator.so"

    execute_and_wait "sed -r -i 's/#if 1 \/\/ ifdef PMVEE_LIBC_MP_HEAP/#ifdef PMVEE_LIBC_MP_HEAP/g' $__remon_glibc_dir/malloc/malloc.c"
    execute_and_wait "sed -r -i 's/#if 1 \/\/ ifdef PMVEE_LIBC_MP_HEAP/#ifdef PMVEE_LIBC_MP_HEAP/g' $__remon_glibc_dir/malloc/arena.c"
    execute_and_wait "sed -r -i 's/#if 1 \/\/ ifdef PMVEE_LIBC_MP_HEAP/#ifdef PMVEE_LIBC_MP_HEAP/g' $__remon_glibc_dir/csu/pmvee-state-agent.c"
    execute_and_wait "sed -r -i 's/#if 1 \/\/ ifdef PMVEE_LIBC_MP_HEAP/#ifdef PMVEE_LIBC_MP_HEAP/g' $__remon_dir/MVEE/Src/MVEE_syscalls_handlers.cpp"
    execute_and_wait "sed -r -i 's/#if 0 \/\/ ifndef PMVEE_NO_ALLOCATOR/#ifndef PMVEE_NO_ALLOCATOR/g' $__remon_dir/MVEE/Src/MVEE_syscalls_handlers.cpp"    
    execute_and_wait "sed -r -i 's/#if 1 \/\/ ifdef PMVEE_LIBC_MP_HEAP/#ifdef PMVEE_LIBC_MP_HEAP/g' $__remon_dir/MVEE/Src/MVEE_variant_launch.cpp"
    execute_and_wait "sed -r -i 's/#elif defined\(PMVEE_ALLOCATOR\)/#elif 1 \/\/ elif defined\(PMVEE_ALLOCATOR\)/g' $__remon_dir/MVEE/Src/MVEE_variant_launch.cpp"

    logf "building ReMon for pmvee allocator"
    execute_and_wait "cd $__remon_dir/build && make enable-ipmon-pmvee && make benchmark && make -j 1>/dev/null"

    logf "building ReMon-glibc for pmvee allocator"
    execute_and_wait "cd $__remon_glibc_dir/build-tree && make -j 1>/dev/null"
}


function set_hardened_allocator
{
    execute_and_wait "sed -r -i 's/#define MAP_PMVEE 0x2000000/\/\/ define MAP_PMVEE 0x2000000/g' $__remon_glibc_dir/malloc/malloc.c"
    execute_and_wait "cd $__benchmark_dir/allocator/hardened_malloc/ && make -B -j N_ARENA=1 CONFIG_EXTENDED_SIZE_CLASSES=false CONFIG_CLASS_REGION_SIZE=8388608"
    execute_and_wait "cp $__benchmark_dir/allocator/hardened_malloc/out/libhardened_malloc.so $__benchmark_dir/allocator/hardened_malloc/native_libhardened_malloc.so"
    execute_and_wait "sed -r -i 's/\/\/ define MAP_PMVEE 0x2000000/#define MAP_PMVEE 0x2000000/g' $__remon_glibc_dir/malloc/malloc.c"
    execute_and_wait "cd $__benchmark_dir/allocator/hardened_malloc/ && make -B -j N_ARENA=1 CONFIG_EXTENDED_SIZE_CLASSES=false CONFIG_CLASS_REGION_SIZE=8388608"
    __pmvee_ld_preload="LD_PRELOAD=$__benchmark_dir/allocator/hardened_malloc/native_libhardened_malloc.so"

    execute_and_wait "sed -r -i 's/#if 1 \/\/ ifdef PMVEE_LIBC_MP_HEAP/#ifdef PMVEE_LIBC_MP_HEAP/g' $__remon_glibc_dir/malloc/malloc.c"
    execute_and_wait "sed -r -i 's/#if 1 \/\/ ifdef PMVEE_LIBC_MP_HEAP/#ifdef PMVEE_LIBC_MP_HEAP/g' $__remon_glibc_dir/malloc/arena.c"
    execute_and_wait "sed -r -i 's/#if 1 \/\/ ifdef PMVEE_LIBC_MP_HEAP/#ifdef PMVEE_LIBC_MP_HEAP/g' $__remon_glibc_dir/csu/pmvee-state-agent.c"
    execute_and_wait "sed -r -i 's/#if 1 \/\/ ifdef PMVEE_LIBC_MP_HEAP/#ifdef PMVEE_LIBC_MP_HEAP/g' $__remon_dir/MVEE/Src/MVEE_syscalls_handlers.cpp"
    execute_and_wait "sed -r -i 's/#if 0 \/\/ ifndef PMVEE_NO_ALLOCATOR/#ifndef PMVEE_NO_ALLOCATOR/g' $__remon_dir/MVEE/Src/MVEE_syscalls_handlers.cpp"    
    execute_and_wait "sed -r -i 's/#if 1 \/\/ ifdef PMVEE_LIBC_MP_HEAP/#ifdef PMVEE_LIBC_MP_HEAP/g' $__remon_dir/MVEE/Src/MVEE_variant_launch.cpp"
    execute_and_wait "sed -r -i 's/#elif 1 \/\/ elif defined\(PMVEE_ALLOCATOR\)/#elif defined\(PMVEE_ALLOCATOR\)/g' $__remon_dir/MVEE/Src/MVEE_variant_launch.cpp"

    logf "building ReMon for hardened allocator"
    execute_and_wait "cd $__remon_dir/build && make enable-ipmon-pmvee && make benchmark && make -j 1>/dev/null"

    logf "building ReMon-glibc for hardened allocator"
    execute_and_wait "cd $__remon_glibc_dir/build-tree && make -j 1>/dev/null"
}


function set_libc_allocator
{
    __pmvee_ld_preload=""
    execute_and_wait "sed -r -i 's/#ifdef PMVEE_LIBC_MP_HEAP/#if 1 \/\/ ifdef PMVEE_LIBC_MP_HEAP/g' $__remon_glibc_dir/malloc/malloc.c"
    execute_and_wait "sed -r -i 's/#ifdef PMVEE_LIBC_MP_HEAP/#if 1 \/\/ ifdef PMVEE_LIBC_MP_HEAP/g' $__remon_glibc_dir/malloc/arena.c"
    execute_and_wait "sed -r -i 's/#ifdef PMVEE_LIBC_MP_HEAP/#if 1 \/\/ ifdef PMVEE_LIBC_MP_HEAP/g' $__remon_glibc_dir/csu/pmvee-state-agent.c"
    execute_and_wait "sed -r -i 's/#ifdef PMVEE_LIBC_MP_HEAP/#if 1 \/\/ ifdef PMVEE_LIBC_MP_HEAP/g' $__remon_dir/MVEE/Src/MVEE_syscalls_handlers.cpp"
    execute_and_wait "sed -r -i 's/#if 0 \/\/ ifndef PMVEE_NO_ALLOCATOR/#ifndef PMVEE_NO_ALLOCATOR/g' $__remon_dir/MVEE/Src/MVEE_syscalls_handlers.cpp"    
    execute_and_wait "sed -r -i 's/#ifdef PMVEE_LIBC_MP_HEAP/#if 1 \/\/ ifdef PMVEE_LIBC_MP_HEAP/g' $__remon_dir/MVEE/Src/MVEE_variant_launch.cpp"
    execute_and_wait "sed -r -i 's/#elif 1 \/\/ elif defined\(PMVEE_ALLOCATOR\)/#elif defined\(PMVEE_ALLOCATOR\)/g' $__remon_dir/MVEE/Src/MVEE_variant_launch.cpp"

    logf "building ReMon for libc allocator"
    execute_and_wait "cd $__remon_dir/build && make enable-ipmon-pmvee && make benchmark && make -j 1>/dev/null"

    logf "building ReMon-glibc for libc allocator"
    execute_and_wait "cd $__remon_glibc_dir/build-tree && make -j 1>/dev/null"
}


function set_no_allocator
{
    __pmvee_ld_preload=""
    execute_and_wait "sed -r -i 's/#if 1 \/\/ ifdef PMVEE_LIBC_MP_HEAP/#ifdef PMVEE_LIBC_MP_HEAP/g' $__remon_glibc_dir/malloc/malloc.c"
    execute_and_wait "sed -r -i 's/#if 1 \/\/ ifdef PMVEE_LIBC_MP_HEAP/#ifdef PMVEE_LIBC_MP_HEAP/g' $__remon_glibc_dir/malloc/arena.c"
    execute_and_wait "sed -r -i 's/#if 1 \/\/ ifdef PMVEE_LIBC_MP_HEAP/#ifdef PMVEE_LIBC_MP_HEAP/g' $__remon_glibc_dir/csu/pmvee-state-agent.c"
    execute_and_wait "sed -r -i 's/#if 1 \/\/ ifdef PMVEE_LIBC_MP_HEAP/#ifdef PMVEE_LIBC_MP_HEAP/g' $__remon_dir/MVEE/Src/MVEE_syscalls_handlers.cpp"
    execute_and_wait "sed -r -i 's/#ifndef PMVEE_NO_ALLOCATOR/#if 0 \/\/ ifndef PMVEE_NO_ALLOCATOR/g' $__remon_dir/MVEE/Src/MVEE_syscalls_handlers.cpp"    
    execute_and_wait "sed -r -i 's/#ifdef PMVEE_LIBC_MP_HEAP/#if 1 \/\/ ifdef PMVEE_LIBC_MP_HEAP/g' $__remon_dir/MVEE/Src/MVEE_variant_launch.cpp"
    execute_and_wait "sed -r -i 's/#elif 1 \/\/ elif defined\(PMVEE_ALLOCATOR\)/#elif defined\(PMVEE_ALLOCATOR\)/g' $__remon_dir/MVEE/Src/MVEE_variant_launch.cpp"

    logf "building ReMon for no allocator"
    execute_and_wait "cd $__remon_dir/build && make enable-ipmon-pmvee && make benchmark && make -j 1>/dev/null"

    logf "building ReMon-glibc for no allocator"
    execute_and_wait "cd $__remon_glibc_dir/build-tree && make -j 1>/dev/null"
}


function set_merge_skip_pmd_kernel
{
    execute_and_wait "sed -r -i 's/#define DEBUG_ME/\/\/ define DEBUG_ME/g' $__remon_dir/PMVEE/pmvee_kernel_module.c"
    execute_and_wait "sed -i 's/#define PMVEE_SKIP_LEVEL.*/#define PMVEE_SKIP_LEVEL PMVEE_KERNEL_MERGE_PMD_SKIP/g' $__remon_dir/PMVEE/pmvee_kernel_module.c"
    execute_and_wait "cd $__remon_dir/PMVEE && make module-install"
}



function set_merge_skip_shorter_pmd_kernel
{
    execute_and_wait "sed -r -i 's/#define DEBUG_ME/\/\/ define DEBUG_ME/g' $__remon_dir/PMVEE/pmvee_kernel_module.c"
    execute_and_wait "sed -i 's/#define PMVEE_SKIP_LEVEL.*/#define PMVEE_SKIP_LEVEL PMVEE_KERNEL_MERGE_PMD_SHORTER_SKIP/g' $__remon_dir/PMVEE/pmvee_kernel_module.c"
    execute_and_wait "cd $__remon_dir/PMVEE && make module-install"
}



function set_merge_skip_pte_kernel
{
    execute_and_wait "sed -r -i 's/#define DEBUG_ME/\/\/ define DEBUG_ME/g' $__remon_dir/PMVEE/pmvee_kernel_module.c"
    execute_and_wait "sed -i 's/#define PMVEE_SKIP_LEVEL.*/#define PMVEE_SKIP_LEVEL PMVEE_KERNEL_MERGE_PTE_SKIP/g' $__remon_dir/PMVEE/pmvee_kernel_module.c"
    execute_and_wait "cd $__remon_dir/PMVEE && make module-install"
}



function set_shortest_skip_kernel
{
    execute_and_wait "sed -r -i 's/#define DEBUG_ME/\/\/ define DEBUG_ME/g' $__remon_dir/PMVEE/pmvee_kernel_module.c"
    execute_and_wait "sed -i 's/#define PMVEE_SKIP_LEVEL.*/#define PMVEE_SKIP_LEVEL PMVEE_KERNEL_SHORTEST_SKIP/g' $__remon_dir/PMVEE/pmvee_kernel_module.c"
    execute_and_wait "cd $__remon_dir/PMVEE && make module-install"
}


function set_skip_kernel
{
    execute_and_wait "sed -r -i 's/#define DEBUG_ME/\/\/ define DEBUG_ME/g' $__remon_dir/PMVEE/pmvee_kernel_module.c"
    execute_and_wait "sed -i 's/#define PMVEE_SKIP_LEVEL.*/#define PMVEE_SKIP_LEVEL PMVEE_KERNEL_SKIP/g' $__remon_dir/PMVEE/pmvee_kernel_module.c"
    execute_and_wait "cd $__remon_dir/PMVEE && make module-install"
}


function set_no_unmap_kernel
{
    execute_and_wait "sed -r -i 's/#define DEBUG_ME/\/\/ define DEBUG_ME/g' $__remon_dir/PMVEE/pmvee_kernel_module.c"
    execute_and_wait "sed -i 's/#define PMVEE_SKIP_LEVEL.*/#define PMVEE_SKIP_LEVEL PMVEE_KERNEL_NO_UNMAP/g' $__remon_dir/PMVEE/pmvee_kernel_module.c"
    execute_and_wait "cd $__remon_dir/PMVEE && make module-install"
}


function set_naive_kernel
{
    execute_and_wait "sed -r -i 's/#define DEBUG_ME/\/\/ define DEBUG_ME/g' $__remon_dir/PMVEE/pmvee_kernel_module.c"
    execute_and_wait "sed -i 's/#define PMVEE_SKIP_LEVEL.*/#define PMVEE_SKIP_LEVEL PMVEE_KERNEL_UNMAP/g' $__remon_dir/PMVEE/pmvee_kernel_module.c"
    execute_and_wait "cd $__remon_dir/PMVEE && make module-install"
}


echo "" > $__log
benchmark_on

execute_and_wait "cd $__orig_remon_dir && ./scripts/switch_patched_binaries.sh ubuntu20 && cd build && make benchmark && make -j 1>/dev/null"

execute_and_wait "killall nginx lighttpd mvee"
while test $# -gt 0
do
    case $1 in
        --merge-skip-pte-kernel)
            set_merge_skip_pte_kernel
            __kernel_module="merge-pte-skip"
            shift
            ;;
        --merge-skip-pmd-kernel)
            set_merge_skip_pmd_kernel
            __kernel_module="merge-pmd-skip"
            shift
            ;;
        --merge-skip-shorter-pmd-kernel)
            set_merge_skip_shorter_pmd_kernel
            __kernel_module="merge-pmd-shorter-skip"
            shift
            ;;
        --shortest-skip-kernel)
            set_shortest_skip_kernel
            __kernel_module="shortest-skip"
            shift
            ;;
        --skip-kernel)
            set_skip_kernel
            __kernel_module="skip"
            shift
            ;;
        --no-unmap-kernel)
            set_no_unmap_kernel
            __kernel_module="no-unmap"
            shift
            ;;
        --naive-kernel)
            set_naive_kernel
            __kernel_module="naive"
            shift
            ;;
        --no-allocator)
            set_no_allocator
            __allocator="none"
            shift
            ;;
        --libc-allocator)
            set_libc_allocator
            __allocator="libc"
            shift
            ;;
        --hardened-allocator)
            set_hardened_allocator
            __allocator="hardened"
            shift
            ;;
        --pmvee-allocator)
            set_pmvee_allocator
            __allocator="pmvee"
            shift
            ;;
        --mapping-count)
            mapping-count-benchmark
            shift
            ;;
        --switcheroo)
            switcheroo-benchmark
            shift
            ;;
        --nginx-workers)
            shift
            ;;
        --nginx-split)
            nginx-benchmark "--ngx-split" ""      4
            shift
            ;;
        --nginx-scan)
            nginx-scan-benchmark "--ngx-split" "" 4
            # nginx-benchmark "--ngx-handler" "-handler"
            shift
            ;;
        --nginx-diffed)
            nginx-diffed-benchmark "--ngx-split" "" 4
            # nginx-benchmark "--ngx-handler" "-handler"
            shift
            ;;
        --nginx-progress)
            nginx-benchmark "--ngx-split" "" 4
            nginx-diffed-benchmark "--ngx-split" "" 4
            nginx-scan-benchmark  "--ngx-split" "" 4
            shift
            ;;
        --nginx)
            nginx-benchmark "--ngx-full"  "-full" 4
            nginx-benchmark "--ngx-split" ""     4
            shift
            ;;
        --lighttpd)
            lighttpd-benchmark "--default" "-default"
            lighttpd-benchmark "--faster"  "-faster"
            shift
            ;;
        --server-micro)
            server-micro-benchmark
            shift
            ;;
        --servers-limited)
            __connections=1
            nginx-benchmark "--ngx-full"  "-full" 1
            nginx-benchmark "--ngx-split" ""     1
            __connections=4
            nginx-benchmark "--ngx-full"  "-full" 4
            nginx-benchmark "--ngx-split" ""     4
            __connections=1
            lighttpd-benchmark "--default" "-default"
            lighttpd-benchmark "--faster"  "-faster"
            __connections=10
            shift
            ;;
        --servers)
            # __connections=1
            nginx-benchmark "--ngx-full"  "-full" 1
            nginx-benchmark "--ngx-split" ""     1
            nginx-diffed-benchmark "--ngx-full"  "-full" 1
            nginx-diffed-benchmark "--ngx-split" ""     1
            nginx-scan-benchmark "--ngx-full"  "-full" 1
            nginx-scan-benchmark "--ngx-split" ""     1
            # __connections=4
            nginx-benchmark "--ngx-full"  "-full" 4
            nginx-benchmark "--ngx-split" ""     4
            nginx-diffed-benchmark "--ngx-full"  "-full" 4
            nginx-diffed-benchmark "--ngx-split" ""     4
            nginx-scan-benchmark "--ngx-full"  "-full" 4
            nginx-scan-benchmark "--ngx-split" ""     4
            # __connections=1
            lighttpd-benchmark "--default" "-default"
            lighttpd-benchmark "--faster"  "-faster"
            # __connections=10
            shift
            ;;
        --paper)
            set_no_allocator
            __allocator="none"

            set_merge_skip_pmd_kernel
            __kernel_module="merge-pmd-skip"

            mapping-count-benchmark
            switcheroo-benchmark

            set_merge_skip_shorter_pmd_kernel
            __kernel_module="merge-pmd-shorter-skip"

            mapping-count-benchmark
            switcheroo-benchmark

            set_pmvee_allocator
            __allocator="pmvee"

            nginx-benchmark "--ngx-full"  "-full" 1
            nginx-benchmark "--ngx-split" ""     1
            nginx-benchmark "--ngx-full"  "-full" 4
            nginx-benchmark "--ngx-split" ""     4
            # nginx-diffed-benchmark "--ngx-full"  "-full" 4
            nginx-diffed-benchmark "--ngx-split" ""     4
            # nginx-scan-benchmark "--ngx-full"  "-full" 4
            nginx-scan-benchmark "--ngx-split" ""     4
            lighttpd-benchmark "--default" "-default"
            lighttpd-benchmark "--faster"  "-faster"

            set_libc_allocator
            __allocator="libc"

            nginx-benchmark "--ngx-split" ""     4
            lighttpd-benchmark "--faster"  "-faster"

            set_pmvee_allocator
            __allocator="pmvee"

            shift
            ;;
        *)
            echo " > unrecognised option $1"
            break
  esac
done

__output_dir_base="./paper-outputs/"

mkdir -p "$__output_dir_base/$__today_output_dir/" || true
mkdir -p "$__output_dir_base/latest/" || true
cp -r "$__output_dir_base"/"$__sub_output_dir"/* "$__output_dir_base/$__today_output_dir/"
cp -r "$__output_dir_base"/"$__sub_output_dir"/* "$__output_dir_base/latest/"

scp -r "$__output_dir_base/latest/" $__benchmark_dir/
ssh -t fortdivide-benchmark $__benchmark_dir/process.py "$__output_dir_base/latest/"
