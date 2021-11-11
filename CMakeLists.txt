cmake_minimum_required(VERSION 3.20)

add_compile_options(
	-Wall
	-Wextra
	-pedantic
	-Werror
)

project(PPtar VERSION "1.0.0")

include(GNUInstallDirs)

set(CMAKE_MODULE_PATH "${CMAKE_CURRENT_LIST_DIR}/vendor/${CMAKE_INSTALL_DATADIR}/cmake/")

file(DOWNLOAD "https://github.com/Petkr/PPstyle/releases/download/1.0.6/PPstyle-1.0.6-Linux.tar.gz" "PPstyle.tar.gz")
file(ARCHIVE_EXTRACT INPUT "PPstyle.tar.gz" DESTINATION "${CMAKE_CURRENT_LIST_DIR}/vendor")

add_subdirectory(PPtar)

set(CPACK_GENERATOR "TGZ")
include(CPack)
