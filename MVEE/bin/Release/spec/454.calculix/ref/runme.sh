BENCHPATH=$SPECPATH/454.calculix
BINPATH=$BENCHPATH/build/$SPECPROFILE
DATAPATH=$BENCHPATH/data/ref/input
ALLDATAPATH=$BENCHPATH/data/all/input

cd $MVEEROOT/MVEE/bin/Release/spec/mvee_run
$BINPATH/calculix -i $DATAPATH/hyperviscoplastic > calculix.out
