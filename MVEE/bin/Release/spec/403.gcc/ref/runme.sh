BENCHPATH=$SPECPATH/403.gcc
BINPATH=$BENCHPATH/build/$SPECPROFILE
DATAPATH=$BENCHPATH/data/ref/input
ALLDATAPATH=$BENCHPATH/data/all/input

cd $MVEEROOT/MVEE/bin/Release/spec/mvee_run
$BINPATH/gcc $DATAPATH/166.in -o 166.s > 166.out
$BINPATH/gcc $DATAPATH/200.in -o 200.s > 200.out
$BINPATH/gcc $DATAPATH/c-typeck.in -o c-typeck.s > c-typeck.out
$BINPATH/gcc $DATAPATH/cp-decl.in -o cp-decl.s > cp-decl.out
$BINPATH/gcc $DATAPATH/expr.in -o expr.s > expr.out
$BINPATH/gcc $DATAPATH/expr2.in -o expr2.s > expr2.out
$BINPATH/gcc $DATAPATH/g23.in -o g23.s > g23.out
$BINPATH/gcc $DATAPATH/s04.in -o s04.s > s04.out
$BINPATH/gcc $DATAPATH/scilab.in -o scilab.s > scilab.out
