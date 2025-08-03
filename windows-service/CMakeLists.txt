# Минимальная версия CMake
cmake_minimum_required(VERSION 3.31)

# Название проекта
project(project)

# Стандарт C++
set(CMAKE_CXX_STANDARD 26)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Настройки для Windows
if(WIN32)
    set(CMAKE_SYSTEM_VERSION 10.0.19041.0)  # Windows 10 SDK
    add_definitions(-DWIN32_LEAN_AND_MEAN)
    add_definitions(-DNOMINMAX)
    add_definitions(-D_WIN32_WINNT=0x0601)  # Windows 7 и выше
endif()

# Конфигурации сборки
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif()

# Настройки компилятора
if(MSVC)
    # Visual Studio настройки
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} /W4 /permissive-")
    set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} /Od /Zi /MDd")
    set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} /O2 /DNDEBUG /MD")

    # Включение параллельной сборки
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} /MP")

    # Отключение предупреждений для внешних библиотек
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} /external:W0")

elseif(CMAKE_COMPILER_IS_GNUCXX)
    # GCC настройки
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Wextra -Wpedantic")
    set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -g -O0")
    set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -O3 -DNDEBUG")
endif()

# Поиск зависимостей
find_package(Threads REQUIRED)

# OpenSSL для TLS и криптографии
find_package(OpenSSL REQUIRED)
if(OpenSSL_FOUND)
    message(STATUS "OpenSSL found: ${OPENSSL_VERSION}")
else()
    message(FATAL_ERROR "OpenSSL not found")
endif()

# gRPC и Protobuf
find_package(Protobuf REQUIRED)
find_package(gRPC REQUIRED)
if(gRPC_FOUND)
    message(STATUS "gRPC found")
else()
    message(FATAL_ERROR "gRPC not found")
endif()

# JSON библиотека (jsoncpp)
find_package(PkgConfig QUIET)
if(PkgConfig_FOUND)
    pkg_check_modules(JSONCPP jsoncpp)
endif()

if(NOT JSONCPP_FOUND)
    # Попытка найти через find_package
    find_package(jsoncpp QUIET)
    if(jsoncpp_FOUND)
        set(JSONCPP_LIBRARIES jsoncpp_lib)
    else()
        # Fallback на vcpkg или системную установку
        find_library(JSONCPP_LIBRARIES NAMES jsoncpp)
        find_path(JSONCPP_INCLUDE_DIRS json/json.h)
    endif()
endif()

# Boost (опционально, для дополнительных утилит)
find_package(Boost COMPONENTS system filesystem thread QUIET)

# Windows-специфичные библиотеки
if(WIN32)
    set(WINDOWS_LIBS
            ws2_32          # Winsock
            advapi32        # Registry, Services API
            kernel32        # System functions
            user32          # User interface
            ole32           # COM
            oleaut32        # OLE Automation
            uuid            # GUID generation
            rpcrt4          # RPC runtime
            netapi32        # Network API
            wtsapi32        # Terminal Services
            userenv         # User environment
            psapi           # Process API
            version         # Version info
            crypt32         # Cryptographic API
            secur32         # Security API
            wintrust        # WinTrust API
    )
endif()

# Определение директорий
set(SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/src)
set(INCLUDE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/include)

# Исходные файлы
set(SERVICE_SOURCES
        ${CMAKE_CURRENT_SOURCE_DIR}/service_main.cpp
        ${SOURCE_DIR}/ipc_comm.cpp
        ${SOURCE_DIR}/network_client.cpp
        ${SOURCE_DIR}/updater.cpp
        ${SOURCE_DIR}/task_router.cpp
        ${SOURCE_DIR}/auth_state.cpp
        ${SOURCE_DIR}/config_loader.cpp
        ${SOURCE_DIR}/logger.cpp
)

# Заголовочные файлы
set(SERVICE_HEADERS
        ${INCLUDE_DIR}/ipc_comm.h
        ${INCLUDE_DIR}/network_client.h
        ${INCLUDE_DIR}/updater.h
        ${INCLUDE_DIR}/task_router.h
        ${INCLUDE_DIR}/auth_state.h
        ${INCLUDE_DIR}/config_loader.h
        ${INCLUDE_DIR}/logger.h
)

# Создание исполняемого файла службы
add_executable(AntivirusService ${SERVICE_SOURCES} ${SERVICE_HEADERS})

# Настройка include директорий
target_include_directories(AntivirusService
        PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}
        ${INCLUDE_DIR}
        ${OPENSSL_INCLUDE_DIR}
        SYSTEM PRIVATE
        ${JSONCPP_INCLUDE_DIRS}
)

# Линковка библиотек
target_link_libraries(AntivirusService
        PRIVATE
        ${CMAKE_THREAD_LIBS_INIT}
        OpenSSL::SSL
        OpenSSL::Crypto
        gRPC::grpc++
        gRPC::grpc
        protobuf::libprotobuf
        ${JSONCPP_LIBRARIES}
)

# Windows-специфичные библиотеки
if(WIN32)
    target_link_libraries(AntivirusService PRIVATE ${WINDOWS_LIBS})
endif()

# Boost библиотеки (если найдены)
if(Boost_FOUND)
    target_link_libraries(AntivirusService PRIVATE
            Boost::system
            Boost::filesystem
            Boost::thread
    )
    target_compile_definitions(AntivirusService PRIVATE BOOST_AVAILABLE)
endif()

# Настройки для Windows Service
if(WIN32)
    # Установка подсистемы Console для службы
    set_target_properties(AntivirusService PROPERTIES
            WIN32_EXECUTABLE FALSE
            LINK_FLAGS "/SUBSYSTEM:CONSOLE"
    )

    # Добавление иконки ресурса (если есть)
    if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/resources/service.rc")
        target_sources(AntivirusService PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/resources/service.rc")
    endif()

    # Манифест для повышенных привилегий
    if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/resources/service.manifest")
        set_property(TARGET AntivirusService PROPERTY
                VS_APPLICATION_MANIFEST "${CMAKE_CURRENT_SOURCE_DIR}/resources/service.manifest")
    endif()
endif()

# Определения препроцессора
target_compile_definitions(AntivirusService
        PRIVATE
        $<$<CONFIG:Debug>:DEBUG _DEBUG>
        $<$<CONFIG:Release>:NDEBUG>
        SERVICE_NAME="AntivirusService"
        SERVICE_VERSION="${PROJECT_VERSION}"
)

# Специальные настройки для разных конфигураций
set_target_properties(AntivirusService PROPERTIES
        DEBUG_POSTFIX "_d"
        RELEASE_POSTFIX ""
)

# Копирование конфигурационных файлов
configure_file(
        "${CMAKE_CURRENT_SOURCE_DIR}/config/service_config.json.in"
        "${CMAKE_BINARY_DIR}/service_config.json"
        @ONLY
)

# Установка файлов
install(TARGETS AntivirusService
        RUNTIME DESTINATION bin
        COMPONENT Service
)

install(FILES
        "${CMAKE_BINARY_DIR}/service_config.json"
        DESTINATION config
        COMPONENT Configuration
)

# Создание инсталлятора (опционально)
if(WIN32)
    # WiX Toolset или NSIS
    set(CPACK_GENERATOR "WIX")
    set(CPACK_PACKAGE_NAME "Antivirus Windows Service")
    set(CPACK_PACKAGE_VENDOR "Antivirus Company")
    set(CPACK_PACKAGE_VERSION "${PROJECT_VERSION}")
    set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "Antivirus Protection Service")
    set(CPACK_PACKAGE_INSTALL_DIRECTORY "Antivirus")

    # Компоненты для установки
    set(CPACK_COMPONENTS_ALL Service Configuration)
    set(CPACK_COMPONENT_SERVICE_DISPLAY_NAME "Antivirus Service")
    set(CPACK_COMPONENT_CONFIGURATION_DISPLAY_NAME "Configuration Files")

    include(CPack)
endif()

# Тесты (опционально)
option(BUILD_TESTS "Build unit tests" OFF)
if(BUILD_TESTS)
    enable_testing()

    # Google Test
    find_package(GTest QUIET)
    if(GTest_FOUND)
        add_subdirectory(tests)
    else()
        message(WARNING "Google Test not found, tests will not be built")
    endif()
endif()

# Документация (опционально)
option(BUILD_DOCS "Build documentation" OFF)
if(BUILD_DOCS)
    find_package(Doxygen QUIET)
    if(Doxygen_FOUND)
        set(DOXYGEN_INPUT_DIR ${CMAKE_CURRENT_SOURCE_DIR})
        set(DOXYGEN_OUTPUT_DIR ${CMAKE_BINARY_DIR}/docs)

        configure_file(
                "${CMAKE_CURRENT_SOURCE_DIR}/docs/Doxyfile.in"
                "${CMAKE_BINARY_DIR}/Doxyfile"
                @ONLY
        )

        add_custom_target(docs
                COMMAND ${DOXYGEN_EXECUTABLE} ${CMAKE_BINARY_DIR}/Doxyfile
                WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
                COMMENT "Generating API documentation with Doxygen"
                VERBATIM
        )
    endif()
endif()

# Статический анализ (опционально)
option(ENABLE_STATIC_ANALYSIS "Enable static analysis tools" OFF)
if(ENABLE_STATIC_ANALYSIS)
    # Clang-tidy
    find_program(CLANG_TIDY_EXE NAMES "clang-tidy")
    if(CLANG_TIDY_EXE)
        set_target_properties(AntivirusService PROPERTIES
                CXX_CLANG_TIDY "${CLANG_TIDY_EXE};-checks=*,-fuchsia-*"
        )
    endif()

    # PVS-Studio (если доступен)
    find_program(PVS_STUDIO_EXE NAMES "pvs-studio-analyzer")
    if(PVS_STUDIO_EXE)
        # Настройка PVS-Studio
    endif()
endif()

# Профайлинг и отладка
option(ENABLE_PROFILING "Enable profiling support" OFF)
if(ENABLE_PROFILING AND CMAKE_BUILD_TYPE STREQUAL "Debug")
    if(MSVC)
        target_compile_options(AntivirusService PRIVATE /PROFILE)
        target_link_options(AntivirusService PRIVATE /PROFILE)
    endif()
endif()

# Копирование DLL зависимостей на Windows
if(WIN32 AND CMAKE_BUILD_TYPE STREQUAL "Debug")
    # Функция для копирования DLL
    function(copy_dll_dependencies target)
        # OpenSSL DLLs
        if(OPENSSL_ROOT_DIR)
            file(GLOB OPENSSL_DLLS "${OPENSSL_ROOT_DIR}/bin/*.dll")
            foreach(dll ${OPENSSL_DLLS})
                add_custom_command(TARGET ${target} POST_BUILD
                        COMMAND ${CMAKE_COMMAND} -E copy_if_different
                        "${dll}" $<TARGET_FILE_DIR:${target}>
                )
            endforeach()
        endif()

        # gRPC DLLs (если доступны)
        # JSON DLLs (если доступны)
    endfunction()

    copy_dll_dependencies(AntivirusService)
endif()

# Информация о сборке
message(STATUS "=== Antivirus Windows Service Build Configuration ===")
message(STATUS "Build type: ${CMAKE_BUILD_TYPE}")
message(STATUS "C++ standard: ${CMAKE_CXX_STANDARD}")
message(STATUS "Compiler: ${CMAKE_CXX_COMPILER_ID} ${CMAKE_CXX_COMPILER_VERSION}")
message(STATUS "OpenSSL version: ${OPENSSL_VERSION}")
message(STATUS "Build tests: ${BUILD_TESTS}")
message(STATUS "Build docs: ${BUILD_DOCS}")
message(STATUS "Static analysis: ${ENABLE_STATIC_ANALYSIS}")
message(STATUS "Profiling: ${ENABLE_PROFILING}")

if(WIN32)
    message(STATUS "Target platform: Windows")
    message(STATUS "Windows SDK: ${CMAKE_SYSTEM_VERSION}")
endif()

if(Boost_FOUND)
    message(STATUS "Boost version: ${Boost_VERSION}")
endif()

message(STATUS "================================================")

# Пост-сборочные действия
add_custom_command(TARGET AntivirusService POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E echo "Build completed successfully"
        COMMAND ${CMAKE_COMMAND} -E echo "Executable: $<TARGET_FILE:AntivirusService>"
        VERBATIM
)

# Создание символических ссылок для удобства разработки (Unix-like системы)
if(UNIX)
    add_custom_command(TARGET AntivirusService POST_BUILD
            COMMAND ${CMAKE_COMMAND} -E create_symlink
            $<TARGET_FILE:AntivirusService>
            ${CMAKE_BINARY_DIR}/antivirus-service
    )
endif()