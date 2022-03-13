# Microbenchmark

Time: . Start from the repo's root directory.

## Automatic

### Native

```bash
./eurosys2022-artifact/benchmarks/scripts/run_microbenchmark.sh
```

### Running in docker

**Method 1**: using the included docker bash script

```bash
./eurosys2022-artifact/docker_control.sh run ./eurosys2022-artifact/benchmarks/scripts/run_microbenchmark.sh
```

**Method 2**: running docker command manually:

```bash
docker run                                                        \
    --security-opt seccomp=unconfined                             \
    -v "./:/home/eval/artifact/" --workdir="/home/eval/artifact/" \
    -it shmvee:ae ./eurosys2022-artifact/benchmarks/scripts/run_microbenchmark.sh
```

## Manual

### Step 0 - docker entrance

**Optional!** Skip if you are running the experiments natively. All following commands are to be run inside the docker
container, unless mentioned otherwise.

**Method 1**: using the included docker bash script

```bash
./eurosys2022-artifact/docker_control.sh run
```

**Method 2**: running docker command manually:

```bash
docker run                                                        \
    --security-opt seccomp=unconfined                             \
    -v "./:/home/eval/artifact/" --workdir="/home/eval/artifact/" \
    -it shmvee:ae bash
```

### Step 1 - setting up the output for automatic processing

```bash
# Clear files containing output.
rm ./eurosys2022-artifact/benchmarks/results/microbenchmark/*
```

### Step 2 - setting up the MVEE

```bash
# Optional for when you want to enable IP-MON, has no effect when kernel is not IP-MON enabled.
cd IP-MON/
ln -fs libipmon-default.so libipmon.so
cd ../


cd MVEE/bin/Release/
# Enable IP-MON by editing MVEE.ini and setting "use_ipmon" to true, has no effect when kernel is not IP-MON enabled.
sed -i "s/\"use_ipmon\" : false/\"use_ipmon\" : true/g" ./MVEE.ini
```

### Step 2 - running the experiments

```bash
# native run, do this 10 times
../../../eurosys2022-artifact/benchmarks/microbenchmark/memcpy >> ../../../eurosys2022-artifact/benchmarks/results/microbenchmark/native.out

# wrapped bursts, do this 10 times
../../../eurosys2022-artifact/benchmarks/scripts/relink_glibc.sh default
./mvee -N 2 -- ../../../eurosys2022-artifact/benchmarks/microbenchmark/memcpy >> ../../../eurosys2022-artifact/benchmarks/results/microbenchmark/default.out

# non-wrapped bursts, do this 10 times
../../../eurosys2022-artifact/benchmarks/scripts/relink_glibc.sh stripped
./mvee -N 2 -- ../../../eurosys2022-artifact/benchmarks/microbenchmark/memcpy >> ../../../eurosys2022-artifact/benchmarks/results/microbenchmark/stripped.out

# make sure the correct libc version is used for later experiments
../../../eurosys2022-artifact/benchmarks/scripts/relink_glibc.sh default
```

### Step 3 - automatic processing

This will output the average of the runs for each buffer size for each experiment. This does not have to be run inside
the docker container, but works either way. Run this from the repo's root.

```bash
./eurosys2022-artifact/benchmarks/scripts/process_microbenchmark.sh
```