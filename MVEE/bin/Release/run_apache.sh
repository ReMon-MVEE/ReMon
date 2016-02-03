CMD="$HOME/MVEE/VARAN/apache_1.3.29/src/httpd"

if [ "$1" == "0" ]
then
	sudo $CMD
else
	sudo ./MVEE $1 -- $CMD
fi
