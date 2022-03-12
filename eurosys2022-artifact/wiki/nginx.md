# Nginx

## Step 0 - setup

Open two terminal windows: 
- server: nginx is started from this terminal
- client: this terminal runs wrk

Ideally, the client terminal is opened on a separate machine connected via a dedicated gigabit ethernet link, to
replicate our evaluation setup.

Client wrk command: `wrk -d 10s -t 1 -c 10 --timeout 10s http:/127.0.0.1:8080 >> outfile`, outfile is mentioned in the
comments between the commands. If you are using separate machines to benchmark nginx, the ip is the ip on the dedicated
link for the machine running nginx.

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
        "-v ./:/home/eval/artifact/" -p 8080:8080 --workdir="/home/eval/artifact/" \
        -it shmvee:ae bash
```

## Step 1 - setting up the MVEE

```bash
# Optional for when you want to enable IP-MON, has no effect when kernel is not IP-MON enabled.
cd IP-MON/
ln -fs libipmon-default.so libipmon.so
cd ../


cd MVEE/bin/Release/
# Enable IP-MON by editing MVEE.ini and setting "use_ipmon" to true, has no effect when kernel is not IP-MON enabled.
```

## Step 2 - run experiments

```bash
# native run, 1 worker, do this 5 times
sed -i "s/.*worker_processes.*/worker_processes  1;/" ../../../eurosys2022-artifact/benchmarks/nginx/conf/nginx.conf
../../../eurosys2022-artifact/benchmarks/out/nginx/base_anon/sbin/nginx
# run the wrk command with "nginx-native-1worker" as outfile in the other terminal and wait for the results
../../../eurosys2022-artifact/benchmarks/out/nginx/base_anon/sbin/nginx -s stop

# non-insturmented shm accesses run, 1 worker, do this 5 times
sed -i "s/.*worker_processes.*/worker_processes  1;/" ../../../eurosys2022-artifact/benchmarks/nginx/conf/nginx.conf
./mvee -N 2 -- ../../../eurosys2022-artifact/benchmarks/out/nginx/default_anon/sbin/nginx
# run the wrk command with "nginx-default-1worker" as outfile in the other terminal and wait for the results
# crtl+c to terminate the MVEE

# insturmented shm accesses run, 1 worker, do this 5 times
sed -i "s/.*worker_processes.*/worker_processes  1;/" ../../../eurosys2022-artifact/benchmarks/nginx/conf/nginx.conf
./mvee -N 2 -- ../../../eurosys2022-artifact/benchmarks/out/nginx/wrapped_anon/sbin/nginx
# run the wrk command with "nginx-wrapped-1worker" as outfile in the other terminal and wait for the results
# crtl+c to terminate the MVEE


# native run, 2 workers, do this 5 times
sed -i "s/.*worker_processes.*/worker_processes  2;/" ../../../eurosys2022-artifact/benchmarks/nginx/conf/nginx.conf
../../../eurosys2022-artifact/benchmarks/out/nginx/base_anon/sbin/nginx
# run the wrk command with "nginx-native-2worker" as outfile in the other terminal and wait for the results
../../../eurosys2022-artifact/benchmarks/out/nginx/base_anon/sbin/nginx -s stop

# non-insturmented shm accesses run, 2 workers, do this 5 times
sed -i "s/.*worker_processes.*/worker_processes  2;/" ../../../eurosys2022-artifact/benchmarks/nginx/conf/nginx.conf
./mvee -N 2 -- ../../../eurosys2022-artifact/benchmarks/out/nginx/default_anon/sbin/nginx
# run the wrk command with "nginx-default-2worker" as outfile in the other terminal and wait for the results
# crtl+c to terminate the MVEE

# insturmented shm accesses run, 2 workers, do this 5 times
sed -i "s/.*worker_processes.*/worker_processes  2;/" ../../../eurosys2022-artifact/benchmarks/nginx/conf/nginx.conf
./mvee -N 2 -- ../../../eurosys2022-artifact/benchmarks/out/nginx/wrapped_anon/sbin/nginx
# run the wrk command with "nginx-wrapped-2worker" as outfile in the other terminal and wait for the results
# crtl+c to terminate the MVEE
```

## Step 3 - automatic processing

If you used a separate client machine, copy all outfiles generated to eurosys2022-artifact/benchmarks/results/nginx.

This will output the average of the 5 runs for each experiment.

```bash
../../../eurosys2022-artifact/benchmarks/scripts/process_nginx.sh
```