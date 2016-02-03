CMD="$HOME/MVEE/VARAN/thttpd-2.26/thttpd -p 22 -d $HOME/MVEE/VARAN/lighttpd-1.4.36.orig/tests/docroot/www/"

if [ "$1" == "0" ]
then
	sudo $CMD
else
	sudo ./MVEE $1 -- $CMD
fi
