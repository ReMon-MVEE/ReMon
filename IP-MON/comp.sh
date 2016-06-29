asm() {
	gcc -fPIC -E ${1}.S -o ${1}_preprocessed.S
	as -ggdb -o ${1}.o ${1}_preprocessed.S
}

compile() {
	gcc -ffixed-r12 -O3  -m64 -fPIC -c -ggdb -o ${1}.o ${1}.cpp
}

# -ffixed-r11 -ffixed-r13

asm MVEE_ipmon_syscall

./generate_headers.rb
compile MVEE_ipmon
#compile MVEE_ipmon_memory

gcc  -shared -fPIC   -lc -ldl -o libipmon.so MVEE_ipmon.o MVEE_ipmon_syscall.o
