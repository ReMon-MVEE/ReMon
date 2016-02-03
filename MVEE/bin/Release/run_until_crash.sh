#!/bin/bash
cancel ()
{
    echo "SIGINT cancel"
    exit 0
}


trap cancel SIGINT

while true
do
    stop=0
    for line in `./MVEE $@ | tee lasterr.log`
    do
	err=`echo $line | grep mismatch`
	if [ "$err" != "" ]
	then
	    stop=1
	fi
	tm=`echo $line | grep real`
	if [ "$tm" != "" ]
	then
	    echo -n "."
	fi
    done
    
    if [ "$stop" == "1" ]
    then
	echo "error log in lasterr.log"
	exit 0
    fi
done
