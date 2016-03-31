#CONFIG="mvee-cache.conf"
CONFIG="mvee.conf"
CMD="$MVEEROOT/Benchmarks/VARAN/lighttpd-1.4.36/src/lighttpd -f $MVEEROOT/Benchmarks/VARAN/lighttpd-1.4.36/$CONFIG -m $MVEEROOT/Benchmarks/VARAN/lighttpd-1.4.36/src/.libs/"

if [ "$1" == "0" ]
then
	sudo $CMD
else
	sudo ./MVEE $1 -- $CMD
fi
