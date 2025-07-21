cmake_minimum_required(VERSION 3.31)
project(project)

set(CMAKE_CXX_STANDARD 26)

add_executable(project main.cpp
        windows-service/service.cpp
        windows-service/network_manager.cpp
        antivirus-core/core_api.cpp
        antivirus-core/core_api.h)
