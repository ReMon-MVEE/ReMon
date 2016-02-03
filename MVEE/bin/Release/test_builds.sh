#!/bin/bash
cd ~/parsec-2.1
echo "The following benchmarks need to be recompiled:"
for i in `find * | grep build\-info`
do 
    is_O3=`grep "\-O3" $i | grep "FLAGS:" | wc -l`
    is_omit_frame_pointer=`grep "\-fno\-omit\-frame\-pointer" $i | grep "FLAGS:" | wc -l`
    is_debug_syms=`grep "\-g" $i| grep "FLAGS:" | wc -l`

    if [ "$is_O3" != "2" ] || [ "$is_omit_frame_pointer" != "0" ] || [ "$is_debug_syms" != "0" ]
    then 
	echo -n "   "
	echo $i | cut -d'/' -f3
    fi
done
cd -
