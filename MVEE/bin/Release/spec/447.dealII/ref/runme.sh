BENCHPATH=$SPECPATH/447.dealII
BINPATH=$BENCHPATH/build/$SPECPROFILE
DATAPATH=$BENCHPATH/data/ref/input
ALLDATAPATH=$BENCHPATH/data/all/input

cd /home/stijn/MVEE/MVEE/bin/Release/spec/mvee_run/447.dealII
$BINPATH/dealII 23 > dealII.out
