asm() {
	gcc -fPIC -E ${1}.S -o ${1}_preprocessed.S
	as -ggdb -o ${1}.o ${1}_preprocessed.S
}

preprocess() {
	gcc -ffixed-r12 -O3  -m64 -fPIC -E -ggdb -o ${1}.p ${1}.cpp
}

compile() {
	gcc -ffixed-r12 -O3  -m64 -fPIC -c -ggdb -o ${1}.o ${1}.cpp
}

# -ffixed-r11 -ffixed-r13

asm MVEE_ipmon_syscall

./generate_headers.rb
preprocess MVEE_ipmon
compile MVEE_ipmon
#compile MVEE_ipmon_memory

gcc -s  -shared -fPIC -lc -ldl -o libipmon.so MVEE_ipmon.o MVEE_ipmon_syscall.o
