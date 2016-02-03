BENCHPATH=$SPECPATH/403.gcc
BINPATH=$BENCHPATH/build/$SPECPROFILE
DATAPATH=$BENCHPATH/data/ref/input
ALLDATAPATH=$BENCHPATH/data/all/input

cd /home/stijn/MVEE/MVEE/bin/Release/spec/mvee_run
$BINPATH/gcc $DATAPATH/166.i -o 166.s > 166.out
$BINPATH/gcc $DATAPATH/200.i -o 200.s > 200.out
$BINPATH/gcc $DATAPATH/c-typeck.i -o c-typeck.s > c-typeck.out
$BINPATH/gcc $DATAPATH/cp-decl.i -o cp-decl.s > cp-decl.out
$BINPATH/gcc $DATAPATH/expr.i -o expr.s > expr.out
$BINPATH/gcc $DATAPATH/expr2.i -o expr2.s > expr2.out
$BINPATH/gcc $DATAPATH/g23.i -o g23.s > g23.out
$BINPATH/gcc $DATAPATH/s04.i -o s04.s > s04.out
$BINPATH/gcc $DATAPATH/scilab.i -o scilab.s > scilab.out
