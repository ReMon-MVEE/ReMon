for id in `cat /proc/sysvipc/shm | sed -r 's/ +/ /g' | cut -d" " -f3,8 | grep " 0" | cut -d" " -f1`
do
	echo "removing shared memory segment with shmid: $id"
	ipcrm -m $id
done
