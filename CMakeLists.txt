cmake_minimum_required(VERSION 3.16)

project(X2R LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# -----------------------------
# InstraX
# -----------------------------

set(INSTRAX_SOURCES
    src/main.cpp
    src/ELFLoader.cpp

    src/ir/IR.cpp
    src/ir/Flagstate.cpp

    src/backend/x86/X86Lifter.cpp

    src/runtime/ElfMapper.cpp
    src/runtime/GuestMemory.cpp
    src/runtime/GuestStack.cpp
    src/runtime/Loader.cpp
)

add_executable(instrax ${INSTRAX_SOURCES})

target_include_directories(instrax PRIVATE
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/src
    ${CMAKE_SOURCE_DIR}/utils
    ${CMAKE_SOURCE_DIR}/ELFIO
)

# -----------------------------
# Dependencies
# -----------------------------

find_package(Threads REQUIRED)
find_package(Zydis REQUIRED)

target_link_libraries(instrax PRIVATE
    Zydis::Zydis
    Threads::Threads
)

# Capstone
target_link_libraries(instrax PRIVATE
    capstone
)

# -----------------------------
# C test program
# -----------------------------

add_executable(test_program
    programs/test.c
)

target_include_directories(test_program PRIVATE
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/src
    ${CMAKE_SOURCE_DIR}/utils
)
