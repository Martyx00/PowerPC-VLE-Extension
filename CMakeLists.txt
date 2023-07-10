cmake_minimum_required(VERSION 3.24)
project(TestPlugin CXX)

set(CMAKE_CXX_STANDARD 17)

set(HEADLESS 1)
find_path(
        BN_API_PATH
        NAMES binaryninjaapi.h
        # List of paths to search for the clone of the api
        HINTS ../.. binaryninjaapi $ENV{BN_API_PATH}
        REQUIRED
)
add_subdirectory(${BN_API_PATH} api)

add_library(${PROJECT_NAME} SHARED library.cpp)

target_link_libraries(${PROJECT_NAME} PUBLIC binaryninjaapi)

bn_install_plugin(${PROJECT_NAME})
