BENCHPATH=$SPECPATH/437.leslie3d
BINPATH=$BENCHPATH/build/$SPECPROFILE
DATAPATH=$BENCHPATH/data/ref/input
ALLDATAPATH=$BENCHPATH/data/all/input

cd $MVEEROOT/MVEE/bin/Release/spec/mvee_run
$BINPATH/leslie3d < $DATAPATH/leslie3d.in > leslie3d.out
