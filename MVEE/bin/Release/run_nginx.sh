CMD="$MVEEROOT/Benchmarks/VARAN/nginx-1.5.12/objs/nginx"

if [ "$1" == "0" ]
then
	sudo $CMD
else
	sudo ./MVEE $1 -- $CMD
fi
