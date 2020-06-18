cmake_minimum_required(VERSION 3.14)
project(SSH VERSION 0.1)

set(SSH_Target_Platform x64 CACHE STRING "Target platform")
set_property(CACHE SSH_Target_Platform PROPERTY STRINGS x64 Linux)

set(SSH_Target_Type Lib CACHE STRING "Target type")
set_property(CACHE SSH_Target_Type PROPERTY STRINGS Lib Exe)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
set(CMAKE_CXX_STANDARD 17)

include(ExternalProject)

add_subdirectory(src)
add_subdirectory(test)
