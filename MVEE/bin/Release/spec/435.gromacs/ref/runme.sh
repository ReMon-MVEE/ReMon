BENCHPATH=$SPECPATH/435.gromacs
BINPATH=$BENCHPATH/build/$SPECPROFILE
DATAPATH=$BENCHPATH/data/ref/input
ALLDATAPATH=$BENCHPATH/data/all/input

mkdir -p $MVEEROOT/MVEE/bin/Release/spec/mvee_run/435.gromacs
cd $MVEEROOT/MVEE/bin/Release/spec/mvee_run/435.gromacs
cp $DATAPATH/gromacs.tpr .
chmod u+w gromacs.tpr
$BINPATH/gromacs -silent -deffnm gromacs -nice 0
