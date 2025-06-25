cmake_minimum_required(VERSION 3.25)

set(CMAKE_C_FLAGS_RELEASE   "-O3 -flto -funroll-loops -fomit-frame-pointer -s -g0 -DNDEBUG" CACHE STRING "" FORCE)
set(CMAKE_CXX_FLAGS_RELEASE "-O3 -flto -funroll-loops -fomit-frame-pointer -s -g0 -DNDEBUG -fvisibility=hidden -fvisibility-inlines-hidden" CACHE STRING "" FORCE)
set(CMAKE_EXE_LINKER_FLAGS_RELEASE "-flto -Wl,--gc-sections -Wl" CACHE STRING "" FORCE)
set(CMAKE_INTERPROCEDURAL_OPTIMIZATION_RELEASE TRUE)

if (NOT DEFINED CMAKE_ANDROID_NDK)
    if (EXISTS ${CMAKE_CURRENT_LIST_DIR}/cmake)
        include(cmake/android.cmake)
        if (EXISTS /Users/reverccqin/Library/Android/sdk/ndk/25.1.8937393)
            init_android_ndk(/Users/reverccqin/Library/Android/sdk/ndk/25.1.8937393)
        elseif (EXISTS /Users/reverccqin/Library/Android/sdk/ndk/25.1.8937393)
            init_android_ndk(/Users/reverccqin/Library/Android/sdk/ndk/25.1.8937393)
        endif ()
    else ()
        message(FATAL_ERROR "can not find cmake tools dir,please clone cmake tools")
    endif ()
    # target_abi must in [armeabi-v7a、arm64-v8a、x86、x86_64]
    # toolchain_name must in [gcc、clang]
    # stl_type must in [c++_static、c++_shared、none、system]
    if (DEFINED target_abi)
        init_android_build(${target_abi} 24 "clang" "c++_static")
    else ()
        init_android_build("arm64-v8a" 24 "clang" "c++_static")
    endif ()
endif ()

project(gumTVM)
if (NOT DEFINED CMAKE_ANDROID_NDK)
    config_toolchain_file()
endif ()
set(CMAKE_CXX_STANDARD 17)


include(FetchContent)
if (ANDROID_ABI STREQUAL "arm64-v8a")
    FetchContent_Declare(
            gum
            URL "file://${CMAKE_CURRENT_LIST_DIR}/prebuild/arm64/frida-gum-devkit-17.2.4-android-arm64.zip"
    )

elseif (ANDROID_ABI STREQUAL "armeabi-v7a")
    FetchContent_Declare(
            gum
            URL "file://${CMAKE_CURRENT_LIST_DIR}/prebuild/arm/frida-gum-devkit-16.6.6-android-arm.tar.xz"
    )
endif ()
FetchContent_MakeAvailable(gum)


set(FRIDA_GUM_LIB_PATH "${gum_SOURCE_DIR}/libfrida-gum.a")
set(FRIDA_GUM_INCLUDE_DIR "${gum_SOURCE_DIR}/")
include_directories(${FRIDA_GUM_INCLUDE_DIR} ./ ./core/)
add_subdirectory(external)
add_library(gumTVM SHARED
        core/gum_init.cpp
        core/gum_init.h
        core/instruction_tracer_manager.cpp
        core/instruction_tracer_manager.h
        core/common.h
        core/custom_hook.cpp
        core/custom_hook.h
        core/init.cpp
        core/init.h
        core/instruction_call_back.cpp
        core/instruction_call_back.h
        core/logger_manager.cpp
        core/logger_manager.h
        core/hex_dump.cpp
        core/hex_dump.h
        core/elfio/elf_types.hpp
        core/elfio/elfio.hpp
        core/elfio/elfio_array.hpp
        core/elfio/elfio_dump.hpp
        core/elfio/elfio_dynamic.hpp
        core/elfio/elfio_header.hpp
        core/elfio/elfio_modinfo.hpp
        core/elfio/elfio_note.hpp
        core/elfio/elfio_relocation.hpp
        core/elfio/elfio_section.hpp
        core/elfio/elfio_segment.hpp
        core/elfio/elfio_strings.hpp
        core/elfio/elfio_symbols.hpp
        core/elfio/elfio_utils.hpp
        core/elfio/elfio_version.hpp
        core/elfio/elfio_versym.hpp
        core/Utils.cpp
        core/Utils.h
)

target_link_libraries(gumTVM PRIVATE ${FRIDA_GUM_LIB_PATH} smjni log )