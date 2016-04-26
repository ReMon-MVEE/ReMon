BENCHPATH=$SPECPATH/465.tonto
BINPATH=$BENCHPATH/build/$SPECPROFILE
DATAPATH=$BENCHPATH/data/ref/input
ALLDATAPATH=$BENCHPATH/data/all/input

mkdir -p $MVEEROOT/MVEE/bin/Release/spec/mvee_run/465.tonto
cd $MVEEROOT/MVEE/bin/Release/spec/mvee_run/465.tonto
cp $DATAPATH/stdin .
$BINPATH/tonto > tonto.out
