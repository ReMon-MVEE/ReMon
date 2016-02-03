BENCHPATH=$SPECPATH/445.gobmk
BINPATH=$BENCHPATH/build/$SPECPROFILE
DATAPATH=$BENCHPATH/data/test/input
ALLDATAPATH=$BENCHPATH/data/all/input

$BINPATH/gobmk --quiet --mode gtp <$DATAPATH/capture.tst >capture.out
$BINPATH/gobmk --quiet --mode gtp <$DATAPATH/connect.tst >connect.out
$BINPATH/gobmk --quiet --mode gtp <$DATAPATH/connect_rot.tst >connect_rot.out
$BINPATH/gobmk --quiet --mode gtp <$DATAPATH/connection.tst >connection.out
$BINPATH/gobmk --quiet --mode gtp <$DATAPATH/connection_rot.tst >connection_rot.out
$BINPATH/gobmk --quiet --mode gtp <$DATAPATH/cutstone.tst >cutstone.out
$BINPATH/gobmk --quiet --mode gtp <$DATAPATH/dniwog.tst >dniwog.out
