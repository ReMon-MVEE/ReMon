HOST="localhost"

for i in `seq 1 5`
do
	memcslap --servers=$HOST:8080 | grep Took | cut -d's' -f1 | cut -d'k' -f2 | tr -d ' ' | tr '.' ','
done
