clang -ggdb -Wall -pthread -DNUMTHREADS=1 -o syscall_stresstest_1_thread syscall_stresstest.c
# g++ -pthread -DNUMTHREADS=2 -o syscall_stresstest_2_threads syscall_stresstest.c
# g++ -pthread -DNUMTHREADS=4 -o syscall_stresstest_4_threads syscall_stresstest.c


# for i in `seq 1 4`
# do
#     cp "syscall_stresstest_1_thread" "syscall_stresstest_1_thread$i"
#     cp "syscall_stresstest_2_threads" "syscall_stresstest_2_threads$i"
#     cp "syscall_stresstest_4_threads" "syscall_stresstest_4_threads$i"
# done
