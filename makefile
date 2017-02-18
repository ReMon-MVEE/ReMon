.PHONY: list

list : 
	@echo "The following build types are supported:"
	@echo "-----------------------------------------------------------------\n"
	@echo "Release: build using make -f makefile.release"
	@echo "Release-with-syms: build using make -f makefile.release-with-syms"
	@echo "Debug: build using make -f makefile.debug"
	@echo "Debug-sanitize: build using make -f makefile.debug-sanitize\n"
	@echo "Please refer to the README for more details"
	
