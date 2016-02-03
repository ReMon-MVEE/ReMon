#CONFIG="mvee-cache.conf"
CONFIG="mvee.conf"
CMD="$HOME/MVEE/VARAN/lighttpd-1.4.36/src/lighttpd -f $HOME/MVEE/VARAN/lighttpd-1.4.36/$CONFIG -m $HOME/MVEE/VARAN/lighttpd-1.4.36/src/.libs/"

if [ "$1" == "0" ]
then
	sudo $CMD
else
	sudo ./MVEE $1 -- $CMD
fi
