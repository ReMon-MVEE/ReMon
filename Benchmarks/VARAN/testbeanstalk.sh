HOST="localhost"

for i in `seq 1 5`
do 
	beanstalkd-benchmark/bin/beanstalkd_benchmark_linux_amd64 -c=10 -h="$HOST:8080" 2>&1 | grep Result | cut -d ':' -f 4 | cut -d'r' -f1 | tr -d ' ' | tr '.' ','
done
