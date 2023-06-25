cmake_minimum_required(VERSION 3.25.0)
project(JormungandrExample)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -static-libstdc++")
set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -static-libstdc++")

set(CLIENT_DIR ${CMAKE_SOURCE_DIR}/../Jormungandr)

add_executable(JormungandrExample JormungandrExample.cpp)
target_include_directories(JormungandrExample PRIVATE ${CLIENT_DIR})

if (MSVC)
    target_compile_options(JormungandrExample PRIVATE /W4 /DUNICODE /D_UNICODE)
else()
    target_compile_options(JormungandrExample PRIVATE -Wall -Wextra -pedantic -DUNICODE -D_UNICODE)
endif()

target_link_libraries(JormungandrExample PRIVATE kernel32 user32)