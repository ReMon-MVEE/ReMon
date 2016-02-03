BENCHPATH=$SPECPATH/416.gamess
BINPATH=$BENCHPATH/build/$SPECPROFILE
DATAPATH=$BENCHPATH/data/ref/input
ALLDATAPATH=$BENCHPATH/data/all/input

cd /home/stijn/MVEE/MVEE/bin/Release/spec/mvee_run/416.gamess
$BINPATH/gamess < $DATAPATH/cytosine.2.config > cytosine.2.out
$BINPATH/gamess < $DATAPATH/h2ocu2+.gradient.config > h2ocu2+.gradient.out
$BINPATH/gamess < $DATAPATH/triazolium.config > triazolium.out
