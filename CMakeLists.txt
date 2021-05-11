cmake_minimum_required(VERSION 3.13)

add_compile_options(
	-Wall
	-Wextra
	-pedantic
	-Werror
)

project(PPtar)

add_executable(mytar "mytar.c")
