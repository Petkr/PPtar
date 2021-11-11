cmake_minimum_required(VERSION 3.20)

add_executable("PPtar" "main.c")
target_compile_features("PPtar" PUBLIC cxx_std_20)

install(TARGETS "PPtar" RUNTIME)

include(PPstyle)
PPstyle("PPtar")
