BENCHPATH=$SPECPATH/403.gcc
BINPATH=$BENCHPATH/build/$SPECPROFILE
DATAPATH=$BENCHPATH/data/train/input
ALLDATAPATH=$BENCHPATH/data/all/input

$BINPATH/gcc $DATAPATH/integrate.i -o integrate.s > integrate.out
