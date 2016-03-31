CMD="$HOME/MVEE/VARAN/redis-3.0.3/src/redis-server $MVEEROOT/Benchmarks/VARAN/redis-3.0.3/redis.conf"

if [ "$1" == "0" ]
then
	sudo $CMD
else
	sudo ./MVEE $1 -- $CMD
fi
