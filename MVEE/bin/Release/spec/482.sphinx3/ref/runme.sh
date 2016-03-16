BENCHPATH=$SPECPATH/482.sphinx3
BINPATH=$BENCHPATH/build/$SPECPROFILE
DATAPATH=$BENCHPATH/data/ref/input
ALLDATAPATH=$BENCHPATH/data/all/input

cd $MVEEROOT/MVEE/bin/Release/spec/mvee_run/482.sphinx3
$BINPATH/sphinx_livepretend ctlfile $DATAPATH args.an4 > an4.log
