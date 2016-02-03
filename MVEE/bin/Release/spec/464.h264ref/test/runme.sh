BENCHPATH=$SPECPATH/464.h264ref
BINPATH=$BENCHPATH/build/$SPECPROFILE
DATAPATH=$BENCHPATH/data/test/input
ALLDATAPATH=$BENCHPATH/data/all/input

$BINPATH/h264ref -d $DATAPATH/foreman_test_encoder_baseline.cfg > foreman_test_baseline_encodelog.out
