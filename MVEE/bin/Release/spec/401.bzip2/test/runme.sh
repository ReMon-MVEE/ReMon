BENCHPATH=$SPECPATH/401.bzip2
BINPATH=$BENCHPATH/build/$SPECPROFILE
DATAPATH=$BENCHPATH/data/test/input
ALLDATAPATH=$BENCHPATH/data/all/input

$BINPATH/bzip2 $ALLDATAPATH/input.program 5 > input.program.out
$BINPATH/bzip2 $DATAPATH/dryer.jpg 2 > dryer.jpg.out
