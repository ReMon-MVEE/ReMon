HOST="localhost"

for i in `seq 1 5`
do
	wrk/wrk -c 10 -t 10 "http://$HOST:8080/" | grep Requests | cut -d':' -f2 | tr -d ' ' | tr '.' ','
done
