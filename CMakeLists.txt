project(pcap-tox)
cmake_minimum_required(VERSION 2.8)
set(SRC_LIST main.cpp
    pcap.cpp
    pcap.h
    textpcap.cpp
    textpcap.h
    sqlitepcap.h
    sqlitepcap.cpp
)

SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} --std=c++11 -O3 -flto -Wall -Wextra -pedantic")
add_executable(${PROJECT_NAME} ${SRC_LIST})
