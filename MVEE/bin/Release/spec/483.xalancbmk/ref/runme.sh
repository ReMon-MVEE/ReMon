BENCHPATH=$SPECPATH/483.xalancbmk
BINPATH=$BENCHPATH/build/$SPECPROFILE
DATAPATH=$BENCHPATH/data/ref/input
ALLDATAPATH=$BENCHPATH/data/all/input

cd $MVEEROOT/MVEE/bin/Release/spec/mvee_run
$BINPATH/Xalan -v $DATAPATH/t5.xml $DATAPATH/xalanc.xsl > ref.out
