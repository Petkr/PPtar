cmake_minimum_required(VERSION 3.20)

add_compile_options(
	-Wall
	-Wextra
	-pedantic
	-Werror
)

project(PPtar)

include("${CMAKE_CURRENT_LIST_DIR}/PPstyle/PPstyle.cmake")

add_subdirectory(PPtar)