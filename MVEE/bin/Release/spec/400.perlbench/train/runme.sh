./perlbench -I./lib diffmail.pl 2 550 15 24 23 100 > diffmail.2.550.15.24.23.100.out 2>/dev/null
./perlbench -I./lib perfect.pl b 3 > perfect.b.3.out  2>/dev/null
./perlbench -I. -I./lib scrabbl.pl < scrabbl.in > scrabbl.out 2>/dev/null
./perlbench -I./lib splitmail.pl 535 13 25 24 1091 > splitmail.535.13.25.24.1091.out  2>/dev/null
./perlbench -I. -I./lib suns.pl > suns.out  2>/dev/null
