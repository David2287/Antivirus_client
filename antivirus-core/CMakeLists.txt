# Минимальная версия CMake
cmake_minimum_required(VERSION 3.31)

# Название проекта
project(project)

# Стандарт C++
set(CMAKE_CXX_STANDARD 26)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_executable(project main.cpp
        windows-service/service.cpp
        windows-service/network_manager.cpp
        antivirus-core/core_api.cpp
        antivirus-core/core_api.h)


# Поиск пакетов
find_package(GTest REQUIRED)
find_package(GMock REQUIRED)

# Включаем директории заголовочных файлов
include_directories(${GTEST_INCLUDE_DIRS})
include_directories(${GMOCK_INCLUDE_DIRS})

# Исходные файлы тестов
set(TEST_SOURCES
        test_scanner.cpp
)

# Создание исполняемого файла тестов
add_executable(test_scanner ${TEST_SOURCES})

# Включение CTest
enable_testing()

# Добавление теста в CTest
add_test(NAME ScannerTests COMMAND test_scanner)

# Компиляционные флаги
target_compile_options(test_scanner PRIVATE
        -Wall
        -Wextra
        -Werror
        -g
        -O0
        --coverage
)

# Линковочные флаги для покрытия кода
target_link_options(test_scanner PRIVATE --coverage)