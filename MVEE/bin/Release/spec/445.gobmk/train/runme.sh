BENCHPATH=$SPECPATH/445.gobmk
BINPATH=$BENCHPATH/build/$SPECPROFILE
DATAPATH=$BENCHPATH/data/train/input
ALLDATAPATH=$BENCHPATH/data/all/input

$BINPATH/gobmk --quiet --mode gtp < $DATAPATH/arb.tst > arb.out
$BINPATH/gobmk --quiet --mode gtp < $DATAPATH/arend.tst > arend.out
$BINPATH/gobmk --quiet --mode gtp < $DATAPATH/arion.tst > arion.out
$BINPATH/gobmk --quiet --mode gtp < $DATAPATH/atari_atari.tst > atari_atari.out
$BINPATH/gobmk --quiet --mode gtp < $DATAPATH/blunder.tst > blunder.out
$BINPATH/gobmk --quiet --mode gtp < $DATAPATH/buzco.tst > buzco.out
$BINPATH/gobmk --quiet --mode gtp < $DATAPATH/nicklas2.tst > nicklas2.out
$BINPATH/gobmk --quiet --mode gtp < $DATAPATH/nicklas4.tst > nicklas4.out
