#!/bin/bash
set -e

cd "$(readlink -f $(dirname ${BASH_SOURCE})/../../../)"

# Clear file containing output for native run.
rm ./eurosys2022-artifact/benchmarks/results/microbenchmarks/native.out
# Clear file containing output for mvee run with burst accesses wrapped.
rm ./eurosys2022-artifact/benchmarks/results/microbenchmarks/default.out
# Clear file containing output for mvee run, without burst accesses wrapped.
rm ./eurosys2022-artifact/benchmarks/results/microbenchmarks/stripped.out


# Optional for when you want to enable IP-MON, has no effect when kernel is not IP-MON enabled.
cd IP-MON/
ln -fs libipmon-default.so libipmon.so
cd ../


cd MVEE/bin/Release/
sed -i "s/\"use_ipmon\" : false/\"use_ipmon\" : true/g" ./MVEE.ini


# Native run
echo " > running native microbenchmarks..."
for __i in {1..10}
do
    echo " > run $__i/10"
    ../../../eurosys2022-artifact/benchmarks/microbenchmarks/memcpy >> ../../../eurosys2022-artifact/benchmarks/results/microbenchmarks/native.out
done

# Wrapped bursts
../../../eurosys2022-artifact/benchmarks/scripts/relink-libc.sh default
echo " > running mvee microbenchmarks with wrapped access..."
for __i in {1..10}
do
    echo " > run $__i/10"
    ./mvee -N 2 -- ../../../eurosys2022-artifact/benchmarks/microbenchmarks/memcpy >> ../../../eurosys2022-artifact/benchmarks/results/microbenchmarks/default.out
done

# Non-wrapped bursts
../../../eurosys2022-artifact/benchmarks/scripts/relink-libc.sh stripped
echo " > running mvee microbenchmarks without wrapped access..."
for __i in {1..10}
do
    echo " > run $__i/10"
    ./mvee -N 2 -- ../../../eurosys2022-artifact/benchmarks/microbenchmarks/memcpy >> ../../../eurosys2022-artifact/benchmarks/results/microbenchmarks/stripped.out
done

# Make sure the correct libc version is used for later experiments.
../../../eurosys2022-artifact/benchmarks/scripts/relink-libc.sh default


# Output result.
../../../eurosys2022-artifact/benchmarks/scripts/process_microbenchmark.sh
