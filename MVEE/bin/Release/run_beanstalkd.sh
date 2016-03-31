CMD="$MVEEROOT/Benchmarks/VARAN/beanstalkd/beanstalkd -p 22"

if [ "$1" == "0" ]
then
	sudo $CMD
else
	sudo ./MVEE $1 -- $CMD
fi
