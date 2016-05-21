set -e
set -u

asm() {
	gcc -fPIC -E ${1}.S -o ${1}_preprocessed.S
	as -ggdb -o ${1}.o ${1}_preprocessed.S
}

compile() {
	gcc -ffixed-r12 -ffixed-r13 -O3  -m64 -fPIC -c -ggdb -S -o ${1}.s ${1}.cpp
	python diablo.py ${1}.s ${1}_inlined.s --inline ipmon_unchecked_syscall asm/ipmon_unchecked_syscall.S --inline ipmon_checked_syscall asm/ipmon_checked_syscall.S --inject ipmon_enclave_entrypoint asm/ipmon_enclave_prologue.S asm/ipmon_enclave_epilogue.S
	gcc -c -o ${1}.o ${1}_inlined.s
}

# -ffixed-r11 -ffixed-r13

echo "--------------------------------------------------------------------------------"
echo "Please ignore any errors that appear from HERE"
echo ">>>"
echo ""
./generate_headers.rb
echo ""
echo "<<<"
echo "Until HERE"
echo "--------------------------------------------------------------------------------"
compile MVEE_ipmon

/usr/bin/ld -shared -fPIC -lc -ldl -o libipmon.so MVEE_ipmon.o
