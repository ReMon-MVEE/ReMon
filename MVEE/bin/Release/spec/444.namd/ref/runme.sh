BENCHPATH=$SPECPATH/444.namd
BINPATH=$BENCHPATH/build/$SPECPROFILE
DATAPATH=$BENCHPATH/data/ref/input
ALLDATAPATH=$BENCHPATH/data/all/input

cd $MVEEROOT/MVEE/bin/Release/spec/mvee_run
$BINPATH/namd --input $ALLDATAPATH/namd.input --iterations 38 --output namd.out > namd_std.out
