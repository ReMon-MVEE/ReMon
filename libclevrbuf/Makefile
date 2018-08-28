CXXFLAGS=-c -fPIC -ggdb -Wall -O3 -std=c++11
TEST=test.cpp
LIB=api.cpp
TEST_OBJS:=$(TEST:%.cpp=%.o)
LIB_OBJS:=$(LIB:%.cpp=%.o)

.PHONY : test all lib clean

all: test lib

%.o: %.cpp
	$(CXX) $(CXXFLAGS) $< -o $@

lib: $(LIB_OBJS)
	$(CXX) -shared -fPIC -o libclevrbuf.so $(LIB_OBJS)

test: $(TEST_OBJS) lib
	$(CXX) -ggdb -o test $(TEST_OBJS) -Wl,-rpath,$(CURDIR) -L$(CURDIR) -lclevrbuf

clean:
	rm -rf test libclevrbuf.so $(TEST_OBJS) $(LIB_OBJS)
