BENCHPATH=$SPECPATH/453.povray
BINPATH=$BENCHPATH/build/$SPECPROFILE
DATAPATH=$BENCHPATH/data/ref/input
ALLDATAPATH=$BENCHPATH/data/all/input

cd $MVEEROOT/MVEE/bin/Release/spec/mvee_run/453.povray
$BINPATH/povray SPEC-benchmark-ref.ini > SPEC-benchmark-ref.out
