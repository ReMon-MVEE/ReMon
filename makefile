SHELL = /bin/sh

#-----------------------------------------------------------------------------
# Architecture
#-----------------------------------------------------------------------------

ifndef _ARCH
  BITS := $(shell getconf LONG_BIT)
  ifeq ($(BITS),32)
    _ARCH := i386
  else
    _ARCH := amd64
  endif
  export _ARCH
endif

#-----------------------------------------------------------------------------
# Build type and directories
#-----------------------------------------------------------------------------

BUILD		= Release
#BUILD      = Release-syms
#BUILD		= Debug
#BUILD		= Debug-sanitize

# directories
MVEE_SRC	= ./MVEE/Src
MVEE_ARCH_SRC	= ./MVEE/Src/arch/$(_ARCH)
MVEE_INC	= ./MVEE/Inc
MVEE_ARCH_INC	= ./MVEE/Inc/arch/$(_ARCH)
MVEE_OUT	= ./MVEE/bin/$(BUILD)
MVEE_BUILD	= ./MVEE/$(BUILD)-$(_ARCH)

#-----------------------------------------------------------------------------
# Source config
#-----------------------------------------------------------------------------

SRC 	 = $(shell find $(MVEE_SRC) -maxdepth 1 -name *.c*)
ARCH_SRC = $(shell find $(MVEE_ARCH_SRC) -maxdepth 1 -name *.c*)
SRCS	 = $(SRC) $(ARCH_SRC)

#-----------------------------------------------------------------------------
# Configuration.
#-----------------------------------------------------------------------------

# Release build.
ifeq ($(BUILD),Release)
BUILD_CXXFLAGS = -flto -ffast-math -march=corei7 -std=c++11 -O3 -Werror -fvisibility=hidden -static
endif

# Release-syms build.
ifeq ($(BUILD),Release-syms)
BUILD_CXXFLAGS = -ffast-math -march=corei7 -std=c++11 -O3 -Werror -fvisibility=hidden -ggdb
endif

# Debug build.
ifeq ($(BUILD),Debug)
BUILD_CXXFLAGS = -ggdb -std=c++11 -pedantic-errors -fno-omit-frame-pointer 
endif

# Debug build with address sanitizer
ifeq ($(BUILD),Debug-sanitize)
BUILD_CXXFLAGS = -ggdb -std=c++11 -pedantic-errors -fno-omit-frame-pointer -fsanitize=address
endif

STD_CXXFLAGS		= -D__LINUX_X86__ $(BUILD_CXXFLAGS) -Wall

ifeq ($(BUILD),Release)
#STD_CXX			= clang++
STD_CXX			= g++
STD_LDFLAGS		= -flto -O3 -static -s
ifeq ($(STD_CXX),clang++)
BC			= $(SRCS:%.cpp=$(MVEE_BUILD)/%.bc)
else
OBJ			= $(SRCS:%.cpp=$(MVEE_BUILD)/%.o)
endif
endif

ifeq ($(BUILD),Release-syms)
#STD_CXX			= clang++
STD_CXX			= g++
STD_LDFLAGS		= -O3 
ifeq ($(STD_CXX),clang++)
BC			= $(SRCS:%.cpp=$(MVEE_BUILD)/%.bc)
else
OBJ			= $(SRCS:%.cpp=$(MVEE_BUILD)/%.o)
endif
endif

ifeq ($(BUILD),Debug)
STD_CXX			= clang++
STD_LDFLAGS		= 
OBJ				= $(SRCS:%.cpp=$(MVEE_BUILD)/%.o)
endif

ifeq ($(BUILD),Debug-sanitize)
STD_CXX			= clang++
STD_LDFLAGS		= -fsanitize=address # -shared
OBJ				= $(SRCS:%.cpp=$(MVEE_BUILD)/%.o)
endif


STD_LIBS		= -ldl -lrt -lelf -lstdc++ -ldwarf -lpthread -lconfig

BIN = $(MVEE_OUT)/MVEE

.PHONY: all clean

all: main-build

pre-build:
	./generate_syscall_tables.rb
	./compile_loader.rb
main-build: pre-build
	@$(MAKE) --no-print-directory target
target: $(BIN) 


# rules for clang -O3 builds
ifdef BC
$(BIN): $(BC)
	@-mkdir -p $(MVEE_OUT)
	llvm-link -o $(MVEE_BUILD)/MVEE-full.bc $^
	opt -O3 $(MVEE_BUILD)/MVEE-full.bc -o $(MVEE_BUILD)/MVEE-full-optimized.bc
	llc -o $(MVEE_BUILD)/MVEE-full-optimized.S $(MVEE_BUILD)/MVEE-full-optimized.bc
	$(STD_CXX) -o $@ $(STD_LDFLAGS) $(MVEE_BUILD)/MVEE-full-optimized.S $(STD_LIBS)

$(MVEE_BUILD)/%.bc: %.cpp
	@-mkdir -p $(MVEE_BUILD)/$(dir $<)
	$(STD_CXX) -I/usr/include -I$(MVEE_INC) -I$(MVEE_ARCH_INC) $(STD_CXXFLAGS) -emit-llvm -MM -MT $@ -MF $(patsubst %.o,%.d,$@) $<
	$(STD_CXX) -I/usr/include -I$(MVEE_INC) -I$(MVEE_ARCH_INC) $(STD_CXXFLAGS) -emit-llvm -c -o $@ $<


# rules for gcc (debug or -O3) and clang (debug) builds
else
DEPS := $(OBJ:.o=.d)

-include $(DEPS)

$(MVEE_BUILD)/%.o: %.cpp
	@-mkdir -p $(MVEE_BUILD)/$(dir $<)
	$(STD_CXX) -I/usr/include -I$(MVEE_INC) -I$(MVEE_ARCH_INC) $(STD_CXXFLAGS) -MM -MT $@ -MF $(patsubst %.o,%.d,$@) $<
	$(STD_CXX) -I/usr/include -I$(MVEE_INC) -I$(MVEE_ARCH_INC) $(STD_CXXFLAGS) -c -o $@ $<

$(BIN): $(OBJ)
	@-mkdir -p $(MVEE_OUT)
	$(STD_CXX) -fuse-ld=bfd -o $@ $(STD_LDFLAGS) $^ $(STD_LIBS)
endif

clean: 
	rm -f $(BIN)
	find $(MVEE_BUILD) -name *.bc | xargs rm -f
	find $(MVEE_BUILD) -name *.o | xargs rm -f
	find $(MVEE_BUILD) -name *.S | xargs rm -f
	rm MVEE_LD_Loader/MVEE_LD_Loader
	rm MVEE_LD_Loader/MVEE_LD_Loader_this*
