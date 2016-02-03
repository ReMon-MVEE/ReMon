grep -rIn "syscall:" Logs/MVEE.log | cut -d'(' -f2 | cut -d')' -f1 | sort | uniq -c
