# fetch latest atomics definitions from gnu webpage
lynx -width=1024 -dump "http://gcc.gnu.org/onlinedocs/gcc/_005f_005fatomic-Builtins.html" | grep ptr | egrep -v 'atomic_is_lock_free|atomic_always_lock_free' > atomics.txt
lynx -width=1024 -dump "http://gcc.gnu.org/onlinedocs/gcc-4.4.5/gcc/Atomic-Builtins.html" | grep ptr > sync.txt

# generate atomic ops enum
echo "/* supported atomic ops */"
echo "enum mvee_atomic_ops {"
grep "\_\_atomic.*(" atomics.txt | cut -d':' -f2 | sed 's/  */ /g' | cut -d' ' -f3 | sed 's/\_\_/\_/' | while read line;
do
    echo "  mvee$line,"
done
grep "\_\_sync.*(" sync.txt | grep -v "    " | sed 's/  */ /g' | cut -d' ' -f3 | sed 's/\_\_/\_/' | while read line;
do
    echo "  mvee$line,"
done
echo "  mvee_atomic_ops_max"
echo "};"
echo " "

# function prototypes
echo "/* interceptable functions */"
echo "#ifdef __cplusplus"
echo "extern \"C\" {"
echo "#endif"
echo "extern unsigned char __attribute__((weak)) mvee_atomic_preop(unsigned short op, void* word_ptr) { return 0; }"
echo "extern void __attribute__((weak)) mvee_atomic_postop(unsigned char __preop_result) {}"
echo "#ifdef __cplusplus"
echo "}"
echo "#endif"
echo " "

# generate call macros to original intrinsics
echo "/* call macros to the original intrinsics */"
grep "\_\_atomic.*(" atomics.txt | cut -d':' -f2 | sed 's/type\|bool\|void\|int\|\*\|size\_t//g' | sed 's/  / /g' | sed 's/ \_\_\(.*\)/#define orig\_\1 \_\_\1/' | sed 's/ (/(/g' | sed 's/( /(/g'
grep "\_\_sync.*(" sync.txt | grep -v "    " | sed 's/type oldval type newval/type oldval, type newval/' | sed 's/  */ /g' | sed 's/type\|bool\|void\|int\|\*\|size\_t//g' | sed 's/  \_\_\(.*\)/#define orig\_\1 \_\_\1/' | sed 's/\(.*\)\.\.\.\(.*\)/\1##\_\_VA\_ARGS\_\_\2/' | sed 's/ (/(/g' | sed 's/( /(/g'
echo " "

# generate mvee wrappers
echo "/* mvee wrappers */"
grep "\_\_atomic.*(" atomics.txt | cut -d':' -f2 | while read line;
do
    func=$line
    stripped_func=`echo $func | sed 's/type\|bool\|void\|int\|\*\|size\_t//g' | sed 's/  / /g'`
    stripped_func_2=`echo $stripped_func | sed 's/\_\_/\_/'`
    func_name=`echo $func | cut -d' ' -f2`
    func_name_2=`echo $func_name | sed 's/\_\_/\_/'`
    func_type=`echo $func | sed 's/ \_\_.*//'`

    if [ "$func_type" == "void" ]
    then
	echo "#define $stripped_func ({ unsigned char __preop_result = mvee_atomic_preop(mvee$func_name_2, (void*)(unsigned long)ptr); orig$stripped_func_2; mvee_atomic_postop(__preop_result); })" | sed 's/( /(/g' | sed 's/ (/(/g' | sed 's/)(/) (/g'
    elif [ "$func_type" == "type" ]
    then
	echo "#define $stripped_func ({ typeof (*ptr + 0) __ret; unsigned char __preop_result = mvee_atomic_preop(mvee$func_name_2, (void*)(unsigned long)ptr); __ret = orig$stripped_func_2; mvee_atomic_postop(__preop_result); __ret; })" | sed 's/( /(/g' | sed 's/ (/(/g' | sed 's/)(/) (/g'
    else
	echo "#define $stripped_func ({ $func_type __ret; unsigned char __preop_result = mvee_atomic_preop(mvee$func_name_2, (void*)(unsigned long)ptr); __ret = orig$stripped_func_2; mvee_atomic_postop(__preop_result); __ret; })" | sed 's/( /(/g' | sed 's/ (/(/g' | sed 's/)(/) (/g'
    fi
done

grep "\_\_sync.*(" sync.txt | grep -v "    " | sed 's/type oldval type newval/type oldval, type newval/' | while read line;
do
    func=$line
    stripped_func=`echo $func | sed 's/type\|bool\|void\|int\|\*\|size\_t//g' | sed 's/  / /g'`
    stripped_func_2=`echo $stripped_func | sed 's/\_\_/\_/'`
    func_name=`echo $func | cut -d' ' -f2`
    func_name_2=`echo $func_name | sed 's/\_\_/\_/'`
    func_type=`echo $func | sed 's/ \_\_.*//'`

    if [ "$func_type" == "void" ]
    then
        echo "#define $stripped_func ({ unsigned char __preop_result = mvee_atomic_preop(mvee$func_name_2, (void*)(unsigned long)ptr); orig$stripped_func_2; mvee_atomic_postop(__preop_result); })" | sed 's/\(.*\)\.\.\.\(.*\)/\1##\_\_VA\_ARGS\_\_\2/' | sed 's/( /(/g' | sed 's/ (/(/g' | sed 's/)(/) (/g'
    elif [ "$func_type" == "type" ]
    then
        echo "#define $stripped_func ({ typeof (*ptr + 0) __ret; unsigned char __preop_result = mvee_atomic_preop(mvee$func_name_2, (void*)(unsigned long)ptr); __ret = orig$stripped_func_2; mvee_atomic_postop(__preop_result); __ret; })" | sed 's/\(.*\)\.\.\.\(.*\)/\1##\_\_VA\_ARGS\_\_\2/' | sed 's/( /(/g' | sed 's/ (/(/g' | sed 's/)(/) (/g'
    else
        echo "#define $stripped_func ({ $func_type __ret; unsigned char __preop_result = mvee_atomic_preop(mvee$func_name_2, (void*)(unsigned long)ptr); __ret = orig$stripped_func_2; mvee_atomic_postop(__preop_result); __ret; })" | sed 's/\(.*\)\.\.\.\(.*\)/\1##\_\_VA\_ARGS\_\_\2/' | sed 's/( /(/g' | sed 's/ (/(/g' | sed 's/)(/) (/g'
    fi
done


rm atomics.txt
rm sync.txt
