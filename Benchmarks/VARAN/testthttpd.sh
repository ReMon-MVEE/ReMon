HOST="localhost"

for i in `seq 1 5`
do
    ab -n 1000 -c 2 http://$HOST:8080/ 2>&1 | grep "Time taken" | cut -d' ' -f7
done
