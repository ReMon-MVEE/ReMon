BENCHPATH=$SPECPATH/456.hmmer
BINPATH=$BENCHPATH/build/$SPECPROFILE
DATAPATH=$BENCHPATH/data/test/input
ALLDATAPATH=$BENCHPATH/data/all/input

$BINPATH/hmmer --fixed 0 --mean 325 --num 45000 --sd 200 --seed 0 $DATAPATH/bombesin.hmm > bombesin.out
