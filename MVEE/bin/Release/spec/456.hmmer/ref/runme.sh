BENCHPATH=$SPECPATH/456.hmmer
BINPATH=$BENCHPATH/build/$SPECPROFILE
DATAPATH=$BENCHPATH/data/ref/input
ALLDATAPATH=$BENCHPATH/data/all/input

cd $MVEEROOT/MVEE/bin/Release/spec/mvee_run
$BINPATH/hmmer $DATAPATH/nph3.hmm $DATAPATH/swiss41 > nph3.out
$BINPATH/hmmer --fixed 0 --mean 500 --num 500000 --sd 350 --seed 0 $DATAPATH/retro.hmm > retro.out
