cmake_minimum_required(VERSION 3.5)
project(dyninst_CFG)

# Retrieve shell environment variables for this, confusingly, the same name 
set(DYNINST_INSTALL $ENV{DYNINST_INSTALL})

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11")

include_directories(${DYNINST_INSTALL}/include)
link_directories(${DYNINST_INSTALL}/lib)

add_executable(bartTestInstrumenter bartTestInstrumenter.cpp)
target_link_libraries(bartTestInstrumenter patchAPI parseAPI symtabAPI dynDwarf dynElf instructionAPI common dyninstAPI boost_system)

