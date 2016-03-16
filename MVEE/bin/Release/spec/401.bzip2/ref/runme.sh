BENCHPATH=$SPECPATH/401.bzip2
BINPATH=$BENCHPATH/build/$SPECPROFILE
DATAPATH=$BENCHPATH/data/ref/input
ALLDATAPATH=$BENCHPATH/data/all/input

cd $MVEEROOT/MVEE/bin/Release/spec/mvee_run
$BINPATH/bzip2 $DATAPATH/input.source 280 > input.source.out
$BINPATH/bzip2 $DATAPATH/chicken.jpg 30 > chicken.jpg.out
$BINPATH/bzip2 $DATAPATH/liberty.jpg 30 > liberty.jpg.out
$BINPATH/bzip2 $ALLDATAPATH/input.program 280 > input.program.out
$BINPATH/bzip2 $DATAPATH/text.html 280 > text.html.out
$BINPATH/bzip2 $ALLDATAPATH/input.combined 200 > input.combined.out
