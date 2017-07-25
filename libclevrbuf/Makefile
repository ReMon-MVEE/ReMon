CXXFLAGS=-c -fPIC -Wall -O3 -std=c++11
TEST=test.cpp
LIB=api.cpp
TEST_OBJS=$(TEST:.cpp=.o)
LIB_OBJS=$(LIB:.cpp=.o)

.PHONY : test all lib

all: $(TEST) $(LIB) test lib

.cpp.o:
	$(CXX) $(CXXFLAGS) $< -o $@

lib: $(LIB_OBJS)
	$(CXX) -shared -fPIC -o libclevrbuf.so $(LIB_OBJS)

test: $(TEST_OBJS)
	$(CXX) -o test $(TEST_OBJS)

clean:
	rm -rf test libclevrbuf.so $(TEST_OBJS) $(LIB_OBJS)
