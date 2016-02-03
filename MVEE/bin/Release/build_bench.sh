find /home/stijn/parsec-2.1/pkgs | grep $1 | grep inst$ | xargs rm -rf
#/home/stijn/parsec-2.1/bin/parsecmgmt -a fullclean -c gcc-pthreads -p $1
/home/stijn/parsec-2.1/bin/parsecmgmt -a build -p $1
