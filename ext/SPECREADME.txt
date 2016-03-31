Setting up SPEC for use in the MVEE:

1) Get the latest SPEC iso and mount it.

2) Create your configs (use the samples in spec/config)

3) build spec
cd /path/to/mounted/spec/iso
./install.sh # choose /path/to/ReMon/ext/spec2006 as your installation folder
cd /path/to/ReMon/ext/spec2006
source shrc
runspec --action=build --size=ref -c <yourconfig without extension> all

4) Some benchmarks need some extra work to set up the inputs:
runspec --action=run --size=ref -c <yourconfig> -n 1 --loose sphinx3 run # you can cancel this as soon as the inputs are unpacked
cd spec/benchspec/CPU2006/482.sphinx3/run/<yourrunfolder>
cp *.raw ../../data/ref/input

5) To run a benchmark inside GHUMVEE, use ./MVEE <demonum> <number of variants>

YAY!
