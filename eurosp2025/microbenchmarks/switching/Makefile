all: native pmvee

native: switcheroo.c dirs
	clang -g -O3 -pie -fPIC -pthread -DNATIVE_RUNNING -o ./bin/switcheroo_native switcheroo.c

pmvee: switcheroo.c dirs
	../../../PMVEE/scripts/stub_builder_too_lazy_to_do_compiler_stuffz_dl.py -i ./switcheroo.json -o ./lib/

	clang -g -I../../../PMVEE/ -DPMVEE_LEADER -DPMVEE_LIBC_COPY \
	-L./lib/ -l:switcheroo_l.so -L../../../PMVEE/ -lpmvee       \
	-O3 -pie -fPIC -o ./bin/switcheroo_pmvee switcheroo.c

	../../../PMVEE/scripts/generate_mappings.py                                                      \
	 	-o  ./bin/switcheroo.pmvee -s switcheroo_extra.json                                          \
		-l  "$(shell readlink -f ./lib/switcheroo_l.so):$(shell readlink -f ./bin/switcheroo_pmvee)" \
		-f  "$(shell readlink -f ./lib/switcheroo_f.so):$(shell readlink -f ./bin/switcheroo_pmvee)" \
		-sc "$(shell readlink -f ./lib/switcheroo_l.so):$(shell readlink -f ./lib/switcheroo_f.so)"  \
		-sm "$(shell readlink -f ./lib/switcheroo_l.so):$(shell readlink -f ./lib/switcheroo_f.so)"

	ln -fs $(shell readlink -f ./lib/switcheroo_l.so) ../../../patched_binaries/gnomelibs/amd64/switcheroo_l.so
	ln -fs $(shell readlink -f ./lib/switcheroo_f.so) ../../../patched_binaries/gnomelibs/amd64/switcheroo_f.so

	ln -fs $(shell readlink -f ./bin/switcheroo.pmvee) ../../pmvee_config/mappings.pmvee

dirs:
	mkdir lib || true
	mkdir bin || true

clean:
	rm -rf ./lib
	rm -rf ./bin
	rm ../../../patched_binaries/gnomelibs/amd64/switcheroo_l.so
	rm ../../../patched_binaries/gnomelibs/amd64/switcheroo_f.so
	