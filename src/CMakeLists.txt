# -----------------------------------------------------------------------------
# Cryptographic Shim Library (ecgroup)
# -----------------------------------------------------------------------------
add_library(ecgroup
  ecgroup.cpp
  keys.cpp
)

message(STATUS "MCL headers will be pulled from: ${mcl_SOURCE_DIR}/include")
message(STATUS "FetchContent binary dir is: ${CMAKE_BINARY_DIR}/_deps/mcl-src")

target_include_directories(ecgroup
  PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
    $<INSTALL_INTERFACE:include>
    $<BUILD_INTERFACE:${mcl_SOURCE_DIR}/include>
)

target_link_libraries(ecgroup PUBLIC mcl)


# -----------------------------------------------------------------------------
# Main C++ Library (bbsgs)
# -----------------------------------------------------------------------------
add_library(bbsgs
  bbsgs.cpp
  keygen.cpp
  helpers.cpp
  signature.cpp
)

target_include_directories(bbsgs
  PUBLIC
    $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:include>
)

target_link_libraries(bbsgs PUBLIC ecgroup)


# -----------------------------------------------------------------------------
# C Wrapper Library for Bindings
# -----------------------------------------------------------------------------
add_library(bbsgs_c_interface STATIC
  bbsgs_c.cpp
)

target_include_directories(bbsgs_c_interface
  PRIVATE
    ${PROJECT_SOURCE_DIR}/include
)

target_link_libraries(bbsgs_c_interface PUBLIC bbsgs)


# -----------------------------------------------------------------------------
# JNI support
# -----------------------------------------------------------------------------
find_package(JNI REQUIRED)
if (JNI_FOUND)
  message(STATUS "Found JNI: ${JNI_VERSION_STRING}")
else()
  message(FATAL_ERROR "JNI not found - please install a JDK or use the Android NDK toolchain")
endif()

# -----------------------------------------------------------------------------
# JNI C++ Library (bbsgs_jni)
# -----------------------------------------------------------------------------
add_library(bbsgs_jni SHARED
  bbsgs_c.cpp
  bbsgs_jni.cpp
)

target_include_directories(bbsgs_jni
  PRIVATE
    ${PROJECT_SOURCE_DIR}/include
    ${JNI_INCLUDE_DIRS}
)

target_link_libraries(bbsgs_jni
  PRIVATE bbsgs
)

set_target_properties(bbsgs_jni PROPERTIES
  POSITION_INDEPENDENT_CODE ON
)
