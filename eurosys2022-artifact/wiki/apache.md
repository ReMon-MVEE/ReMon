# Apache

Time required: ~15 minutes. Start from the repo's root directory.

## Step 0 - setup

Open two terminal windows: 
- server: apache is started from this terminal
- client: this terminal runs wrk

Ideally, the client terminal is opened on a separate machine connected via a dedicated gigabit ethernet link, to
replicate our evaluation setup.

Client wrk command: `wrk -d 10s -t 1 -c 10 --timeout 10s http://127.0.0.1:8080 >> outfile`, outfile is mentioned in the
comments between the commands. If you are using separate machines to benchmark apache, the ip is the ip on the dedicated
link for the machine running apache.

**If you are using docker**: enter the docker container in the server window, either manually or by using the
docker_control.sh script.

**Method 1**: using the included docker bash script

```bash
./eurosys2022-artifact/docker_control.sh run
```

**Method 2**: running docker command manually:

```bash
docker run                                                                     \
    --security-opt seccomp=unconfined                                          \
    -v "./:/home/eval/artifact/" -p 8080:8080 --workdir="/home/eval/artifact/" \
    -it shmvee:ae bash
```

## Step 1 - setting up the MVEE

```bash
# Optional for when you want to enable IP-MON, has no effect when kernel is not IP-MON enabled.
cd IP-MON/
ln -fs libipmon-apache.so libipmon.so
cd ../


cd MVEE/bin/Release/
# Enable IP-MON by editing MVEE.ini and setting "use_ipmon" to true, has no effect when kernel is not IP-MON enabled.
sed -i "s/\"use_ipmon\" : false/\"use_ipmon\" : true/g" ./MVEE.ini
```

## Step 2 - run experiments

```bash
# native run, 1 worker, do this 5 times
sed -i "s/.*ServerLimit.*/ServerLimit 1/" ../../../eurosys2022-artifact/benchmarks/out/apache/base/conf/httpd.conf
../../../eurosys2022-artifact/benchmarks/out/apache/base/bin/apachectl start
# run the wrk command with "apache-native-1worker" as outfile in the other terminal and wait for the results
../../../eurosys2022-artifact/benchmarks/out/apache/base/bin/apachectl stop

# non-instrumented shm accesses run, 1 worker, do this 5 times
sed -i "s/.*ServerLimit.*/ServerLimit 1/" ../../../eurosys2022-artifact/benchmarks/out/apache/default/conf/httpd.conf
./mvee -N 2 -- ../../../eurosys2022-artifact/benchmarks/out/apache/default/bin/apachectl start
# run the wrk command with "apache-default-1worker" as outfile in the other terminal and wait for the results
# crtl+c to terminate the MVEE

# instrumented shm accesses run, 1 worker, do this 5 times
sed -i "s/.*ServerLimit.*/ServerLimit 1/" ../../../eurosys2022-artifact/benchmarks/out/apache/wrapped/conf/httpd.conf
./mvee -N 2 -- ../../../eurosys2022-artifact/benchmarks/out/apache/wrapped/bin/apachectl start
# run the wrk command with "apache-wrapped-1worker" as outfile in the other terminal and wait for the results
# crtl+c to terminate the MVEE


# native run, 2 workers, do this 5 times
sed -i "s/.*ServerLimit.*/ServerLimit 2/" ../../../eurosys2022-artifact/benchmarks/out/apache/base/conf/httpd.conf
../../../eurosys2022-artifact/benchmarks/out/apache/base/bin/apachectl start
# run the wrk command with "apache-native-2worker" as outfile in the other terminal and wait for the results
../../../eurosys2022-artifact/benchmarks/out/apache/base/bin/apachectl stop

# non-instrumented shm accesses run, 2 workers, do this 5 times
sed -i "s/.*ServerLimit.*/ServerLimit 2/" ../../../eurosys2022-artifact/benchmarks/out/apache/default/conf/httpd.conf
./mvee -N 2 -- ../../../eurosys2022-artifact/benchmarks/out/apache/default/bin/apachectl start
# run the wrk command with "apache-default-2worker" as outfile in the other terminal and wait for the results
# crtl+c to terminate the MVEE

# instrumented shm accesses run, 2 workers, do this 5 times
sed -i "s/.*ServerLimit.*/ServerLimit 2/" ../../../eurosys2022-artifact/benchmarks/out/apache/wrapped/conf/httpd.conf
./mvee -N 2 -- ../../../eurosys2022-artifact/benchmarks/out/apache/wrapped/bin/apachectl start
# run the wrk command with "apache-wrapped-2worker" as outfile in the other terminal and wait for the results
# crtl+c to terminate the MVEE
```

## Step 3 - automatic processing

If you used a separate client machine, copy all outfiles generated to eurosys2022-artifact/benchmarks/results/apache.

This will output the average of the runs for each experiment. This does not have to be run inside the docker container,
but works either way. Run this from the repo's root.

```bash
./eurosys2022-artifact/benchmarks/scripts/process_apache.sh
```