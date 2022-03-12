# Microbenchmark

## Automatic

```bash
./eurosys2022-artifact/benchmarks/scripts/run_microbenchmark.sh
```

## Manual

## Step 0 - docker entrance

**Optional!** Skip if you are running the experiments natively.

## Step 1 - setting up the output for automatic processing

```bash
# Clear file containing output for native run.
rm ./eurosys2022-artifact/benchmarks/results/microbenchmarks/native.out
# Clear file containing output for mvee run with burst accesses wrapped.
rm ./eurosys2022-artifact/benchmarks/results/microbenchmarks/default.out
# Clear file containing output for mvee run, without burst accesses wrapped.
rm ./eurosys2022-artifact/benchmarks/results/microbenchmarks/stripped.out
```

## Step 2 - setting up the MVEE

```bash
# Optional for when you want to enable IP-MON, has no effect when kernel is not IP-MON enabled.
cd IP-MON/
ln -fs libipmon-default.so libipmon.so
cd ../


cd MVEE/bin/Release/
# Enable IP-MON by editing MVEE.ini and setting "use_ipmon" to true, has no effect when kernel is not IP-MON enabled.
sed -i "s/\"use_ipmon\" : false/\"use_ipmon\" : true/g" ./MVEE.ini
```

## Step 2 - running the experiments

```bash
# native run, do this 10 times
../../../eurosys2022-artifact/benchmarks/microbenchmarks/memcpy >> ../../../eurosys2022-artifact/benchmarks/results/microbenchmarks/native.out

# wrapped bursts, do this 10 times
../../../eurosys2022-artifact/benchmarks/scripts/relink-libc.sh default
./mvee -N 2 -- ../../../eurosys2022-artifact/benchmarks/microbenchmarks/memcpy >> ../../../eurosys2022-artifact/benchmarks/results/microbenchmarks/default.out

# non-wrapped bursts, do this 10 times
../../../eurosys2022-artifact/benchmarks/scripts/relink-libc.sh stripped
./mvee -N 2 -- ../../../eurosys2022-artifact/benchmarks/microbenchmarks/memcpy >> ../../../eurosys2022-artifact/benchmarks/results/microbenchmarks/stripped.out

# make sure the correct libc version is used for later experiments
../../../eurosys2022-artifact/benchmarks/scripts/relink-libc.sh default
```

## Step 3 - automatic processing

This will output the average of 10 runs for each buffer size for each experiment.

```bash
../../../eurosys2022-artifact/benchmarks/scripts/process_microbenchmark.sh
```