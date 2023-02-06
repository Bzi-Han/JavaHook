cmake_minimum_required(VERSION 3.0.0)

set(ANDROID_PLATFORM android-27)
set(ANDROID_ABI arm64-v8a)
set(NDK_PATH E:/Android/Ndk/android-ndk-r25b)

set(CMAKE_TOOLCHAIN_FILE ${NDK_PATH}/build/cmake/android.toolchain.cmake)

project(JavaHook VERSION 0.0.1 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)

include_directories(
    modules
)

find_library(log-lib log)

add_executable(test src/test.cc)
target_link_libraries(test ${log-lib})