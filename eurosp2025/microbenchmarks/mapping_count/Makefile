all: pmvee native base

base: mapping_count.c dirs
	clang -g -O3 -pie -fPIC -o ./bin/mapping_count mapping_count.c

native: mapping_count.c dirs
	clang -g -O3 -pie -fPIC -pthread -DFULL_NATIVE_RUNNING      -o ./bin/mapping_count_native mapping_count.c
	clang -g -O3 -pie -fPIC -pthread -DFULL_NATIVE_RUNNING_SYNC -o ./bin/mapping_count_native_sync mapping_count.c

pmvee: mapping_count.c dirs
	../../../PMVEE/scripts/stub_builder_too_lazy_to_do_compiler_stuffz_dl.py -i ./mapping_count.json -o ./lib/

	clang -g -I../../../PMVEE/ -DPMVEE_LEADER -DPMVEE_LIBC_COPY \
	-L./lib/ -l:mapping_count_l.so -L../../../PMVEE/ -lpmvee    \
	-O3 -pie -fPIC -o ./bin/mapping_count_pmvee mapping_count.c

	../../../PMVEE/scripts/generate_mappings.py                                                                 \
	 	-o  ./bin/mapping_count.pmvee -s mapping_count.json                                                    \
		-l  "$(shell readlink -f ./lib/mapping_count_l.so)" -f "$(shell readlink -f ./lib/mapping_count_f.so)" \
		-sc "$(shell readlink -f ./lib/mapping_count_l.so):$(shell readlink -f ./lib/mapping_count_f.so)"      \
		-sm "$(shell readlink -f ./lib/mapping_count_l.so):$(shell readlink -f ./lib/mapping_count_f.so)"

	ln -fs $(shell readlink -f ./lib/mapping_count_l.so) ../../../patched_binaries/gnomelibs/amd64/mapping_count_l.so
	ln -fs $(shell readlink -f ./lib/mapping_count_f.so) ../../../patched_binaries/gnomelibs/amd64/mapping_count_f.so

	ln -fs $(shell readlink -f ./bin/mapping_count.pmvee) ../../pmvee_config/mappings.pmvee

dirs:
	mkdir lib || true
	mkdir bin || true

clean:
	rm -rf ./lib
	rm -rf ./bin
	rm ../../../patched_binaries/gnomelibs/amd64/mapping_count_l.so
	rm ../../../patched_binaries/gnomelibs/amd64/mapping_count_f.so
	