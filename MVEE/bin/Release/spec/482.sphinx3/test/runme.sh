BENCHPATH=$SPECPATH/482.sphinx3
BINPATH=$BENCHPATH/build/$SPECPROFILE
DATAPATH=$BENCHPATH/data/test/input
ALLDATAPATH=$BENCHPATH/data/all/input

$BINPATH/sphinx_livepretend ctlfile $DATAPATH $DATAPATH/args.an4 > an4.log
