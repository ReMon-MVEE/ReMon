BENCHPATH=$SPECPATH/400.perlbench
BINPATH=$BENCHPATH/build/$SPECPROFILE
DATAPATH=$BENCHPATH/data/ref/input
ALLDATAPATH=$BENCHPATH/data/all/input

cd $MVEEROOT/MVEE/bin/Release/spec/mvee_run/400.perlbench
$BINPATH/perlbench -I$ALLDATAPATH/lib $DATAPATH/checkspam.pl 2500 5 25 11 150 1 1 1 1 > checkspam.2500.5.25.11.150.1.1.1.1.out
$BINPATH/perlbench -I$ALLDATAPATH/lib $ALLDATAPATH/diffmail.pl 4 800 10 17 19 300 > diffmail.4.800.10.17.19.300.out
$BINPATH/perlbench -I$ALLDATAPATH/lib $ALLDATAPATH/splitmail.pl 1600 12 26 16 4500 > splitmail.1600.12.26.16.4500.out
