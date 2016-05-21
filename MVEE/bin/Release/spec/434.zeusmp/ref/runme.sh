BENCHPATH=$SPECPATH/434.zeusmp
BINPATH=$BENCHPATH/build/$SPECPROFILE
DATAPATH=$BENCHPATH/data/ref/input
ALLDATAPATH=$BENCHPATH/data/all/input

mkdir -p $MVEEROOT/MVEE/bin/Release/spec/mvee_run/434.zeusmp
cd $MVEEROOT/MVEE/bin/Release/spec/mvee_run/434.zeusmp
cp $DATAPATH/* .
$BINPATH/zeusmp > zeusmp.out
