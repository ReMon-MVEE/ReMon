BENCHPATH=$SPECPATH/445.gobmk
BINPATH=$BENCHPATH/build/$SPECPROFILE
DATAPATH=$BENCHPATH/data/ref/input
ALLDATAPATH=$BENCHPATH/data/all/input

cd $MVEEROOT/MVEE/bin/Release/spec/mvee_run
$BINPATH/gobmk --quiet --mode gtp < $DATAPATH/13x13.tst > 13x13.out
$BINPATH/gobmk --quiet --mode gtp < $DATAPATH/nngs.tst > nngs.out
$BINPATH/gobmk --quiet --mode gtp < $DATAPATH/score2.tst > score2.out
$BINPATH/gobmk --quiet --mode gtp < $DATAPATH/trevorc.tst > trevorc.out
$BINPATH/gobmk --quiet --mode gtp < $DATAPATH/trevord.tst > trevord.out
