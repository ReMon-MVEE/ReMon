BENCHPATH=$SPECPATH/464.h264ref
BINPATH=$BENCHPATH/build/$SPECPROFILE
DATAPATH=$BENCHPATH/data/ref/input
ALLDATAPATH=$BENCHPATH/data/all/input

cd $ALLDATAPATH
$BINPATH/h264ref -d $DATAPATH/foreman_ref_encoder_baseline.cfg > foreman_ref_baseline_encodelog.out 
$BINPATH/h264ref -d $DATAPATH/foreman_ref_encoder_main.cfg > foreman_ref_main_encodelog.out 
cd -
cd $DATAPATH
$BINPATH/h264ref -d $DATAPATH/sss_encoder_main.cfg > sss_main_encodelog.out 
cd -
