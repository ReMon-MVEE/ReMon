Setting up SPEC for use in the MVEE:

1) Get the latest SPEC iso and mount it.

2) Create your configs (use the samples in spec/config)

3) build spec
cd /path/to/mounted/spec/iso
./install.sh # choose /path/to/ReMon/ext/spec2006 as your installation folder
cd /path/to/ReMon/ext/spec2006
source shrc
cp /path/to/your/spec/config/<your config> config/
runspec --action=build --size=ref -c <your config without extension or path> all

4) Some benchmarks need some extra work to set up the inputs:
runspec --action=run --size=ref -c <your config without extension or path> -n 1 --loose sphinx3 run # you can cancel this as soon as the inputs are unpacked
cd benchspec/CPU2006/482.sphinx3/run/<yourrunfolder>
cp *.raw ../../data/ref/input

5) To run a benchmark inside GHUMVEE, use ./MVEE <demonum> <number of variants>
Make sure that the name returned by mvee::get_spec_profile in MVEE/Src/MVEE_demos.cpp matches the name of your config!!

YAY!
