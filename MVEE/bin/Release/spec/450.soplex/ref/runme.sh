BENCHPATH=$SPECPATH/450.soplex
BINPATH=$BENCHPATH/build/$SPECPROFILE
DATAPATH=$BENCHPATH/data/ref/input
ALLDATAPATH=$BENCHPATH/data/all/input

cd $MVEEROOT/MVEE/bin/Release/spec/mvee_run
$BINPATH/soplex -s1 -e -m45000 $DATAPATH/pds-50.mps > pds-50.mps.out
$BINPATH/soplex -m3500 $DATAPATH/ref.mps > ref.out
