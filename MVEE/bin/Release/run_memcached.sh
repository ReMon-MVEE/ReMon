CMD="$HOME/MVEE/VARAN/memcached-1.4.17/memcached -p 22 -u root"

if [ "$1" == "0" ]
then
	sudo $CMD
else
	sudo ./MVEE $1 -- $CMD
fi
