cmake_minimum_required(VERSION 3.16)
project(hal_qos C)

set(CMAKE_C_STANDARD 11)

include_directories(.)

add_executable(hal_qos
        classification.c
        classification.h
        queue.c
        queue.h
        timehandler.c
        timehandler.h datastruct_params.h)
