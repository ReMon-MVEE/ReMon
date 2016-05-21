BENCHPATH=$SPECPATH/473.astar
BINPATH=$BENCHPATH/build/$SPECPROFILE
DATAPATH=$BENCHPATH/data/ref/input
ALLDATAPATH=$BENCHPATH/data/all/input

cd $MVEEROOT/MVEE/bin/Release/spec/mvee_run/473.astar
$BINPATH/astar $DATAPATH/BigLakes2048.cfg > BigLakes2048.out
$BINPATH/astar $DATAPATH/rivers.cfg > rivers.out
