BENCHPATH=$SPECPATH/435.gromacs
BINPATH=$BENCHPATH/build/$SPECPROFILE
DATAPATH=$BENCHPATH/data/ref/input
ALLDATAPATH=$BENCHPATH/data/all/input

cd /home/stijn/MVEE/MVEE/bin/Release/spec/mvee_run/435.gromacs
cp ~/spec2006/spec2006/benchspec/CPU2006/435.gromacs/data/ref/input/gromacs.tpr .
chmod u+w gromacs.tpr
$BINPATH/gromacs -silent -deffnm gromacs -nice 0
