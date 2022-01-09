cmake_minimum_required(VERSION 3.16.1)
project(tests C)

set(CMAKE_C_STANDARD 99)

add_executable(tests classification.c classification.h)
