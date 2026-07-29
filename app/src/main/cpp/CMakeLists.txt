cmake_minimum_required(VERSION 3.10)
project(TEESimulator)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fno-rtti")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fno-exceptions")

# LSPlt configuration
OPTION(LSPLT_BUILD_SHARED OFF)
add_subdirectory(external/LSPlt/lsplt/src/main/jni)

add_compile_definitions(BINDER_DISABLE_NATIVE_HANDLE)
add_library(utils_stub SHARED stub/stub_utils.cpp)
target_include_directories(utils_stub PUBLIC external/AOSP/include)

add_library(binder_stub SHARED stub/stub_binder.cpp)
target_include_directories(binder_stub PUBLIC external/AOSP/include)
target_link_libraries(binder_stub PRIVATE utils_stub)

add_executable(libinject.so inject/main.cpp inject/utils.cpp)
target_include_directories(libinject.so PUBLIC include)
target_link_libraries(libinject.so PRIVATE lsplt_static)

add_library(${CMAKE_PROJECT_NAME} SHARED binder_interceptor.cpp)
target_include_directories(
    ${CMAKE_PROJECT_NAME}
    PUBLIC
        external/AOSP/include
        external/AOSP/android16/include_platform
        external/linux-kernel/include
        include
)
target_link_options(${CMAKE_PROJECT_NAME} PRIVATE "-Wl,--allow-shlib-undefined")
target_link_libraries(
    ${CMAKE_PROJECT_NAME}
    PRIVATE
        android
        binder_ndk
        binder_stub
        log
        lsplt_static
        utils_stub
)
