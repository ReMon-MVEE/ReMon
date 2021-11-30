asm() {
	gcc -fPIC -E ${1}.S -o ${1}_preprocessed.S
	as -o ${1}.o ${1}_preprocessed.S
}

preprocess() {
	gcc -z noexecstack -ggdb -ffixed-r12 -O0  -m64 -fPIC -E -o ${1}.p ${1}.cpp
}

compile() {
	gcc -z noexecstack -ggdb -ffixed-r12 -O0  -m64 -fPIC -c -o ${1}.o ${1}.cpp
}

asm MVEE_ipmon_syscall

./generate_headers.rb
preprocess MVEE_ipmon
compile MVEE_ipmon

gcc -z noexecstack -ggdb -shared -O0 -fPIC -lc -ldl -o libipmon.so MVEE_ipmon.o MVEE_ipmon_syscall.o
