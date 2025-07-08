# CMake minimum version required
cmake_minimum_required(VERSION 3.15 FATAL_ERROR)

# -----------------------------------------------------------------------------
# Project Definition
# -----------------------------------------------------------------------------
# Define the project name, version, and language
project(bbsgs VERSION 1.0.0 LANGUAGES C CXX)

# -----------------------------------------------------------------------------
# C++ Standard Configuration
# -----------------------------------------------------------------------------
# Set the C++ standard to C++17. This ensures that modern language features
# are available. The 'REQUIRED' keyword means CMake will fail if the compiler
# doesn't support C++17.
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

message(STATUS "Building bbsgs Version: ${PROJECT_VERSION}")

# -----------------------------------------------------------------------------
# Build Options
# -----------------------------------------------------------------------------
option(BUILD_BBSGS_TESTING "Build the tests" ON)
option(BUILD_BBSGS_BENCHMARK "Build the benchmarks" ON)

message(STATUS "BUILD_BBSGS_TESTING: ${BUILD_BBSGS_TESTING}")
message(STATUS "BUILD_BBSGS_BENCHMARK: ${BUILD_BBSGS_BENCHMARK}")

# Make all targets (static and shared) position‐independent by default
set(CMAKE_POSITION_INDEPENDENT_CODE ON)


# -----------------------------
# Dependencies
# -----------------------------
include(FetchContent)

# -----------------------------------------------------------------------------
# Subdirectory Processing
# -----------------------------------------------------------------------------
add_subdirectory(src)

if(BUILD_BBSGS_TESTING)
    enable_testing()
    add_subdirectory(tests)
endif()

if(BUILD_BBSGS_BENCHMARK)
	add_subdirectory(benchmarks)
endif()

# -----------------------------------------------------------------------------
# Installation Rules (all libraries in one shot)
# -----------------------------------------------------------------------------
install(TARGETS
	ecgroup            # shim library
    bbsgs              # core library
    bbsgs_c_interface  # shared C wrapper
  	ARCHIVE  DESTINATION lib
  	LIBRARY  DESTINATION lib
  	RUNTIME  DESTINATION bin
)

 # Install the public header files.
 install(DIRECTORY include/
         DESTINATION include)

 # Install pkg-config file
 configure_file(
   ${CMAKE_SOURCE_DIR}/bbsgs.pc.in
   ${CMAKE_BINARY_DIR}/bbsgs.pc
   @ONLY
 )
 install(
   FILES ${CMAKE_BINARY_DIR}/bbsgs.pc
   DESTINATION lib/pkgconfig
 )
