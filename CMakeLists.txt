cmake_minimum_required(VERSION 3.0)

project(test_memfd_exec LANGUAGES C)

add_executable(test_memfd_exec main.c)

install(TARGETS test_memfd_exec RUNTIME DESTINATION bin)
