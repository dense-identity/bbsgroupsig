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

if (BUILD_BBSGS_JNI)
  # -----------------------------------------------------------------------------
  # JNI C++ Library (bbsgs_jni)
  # -----------------------------------------------------------------------------
  # This library should ONLY contain the JNI-specific implementation.
  add_library(bbsgs_jni SHARED
    bbsgs_jni.cpp
  )

  target_include_directories(bbsgs_jni
    PRIVATE
      # The C header is in the project's include directory
      ${PROJECT_SOURCE_DIR}/include
      # Headers for JNI itself
      ${JNI_INCLUDE_DIRS}
  )

  # Link against the C wrapper library, which in turn links against the core C++ lib.
  # This creates the correct dependency chain: bbsgs_jni -> bbsgs_c_interface -> bbsgs -> mcl
  target_link_libraries(bbsgs_jni
    PRIVATE
      bbsgs_c_interface
  )

  set_target_properties(bbsgs_jni PROPERTIES
    POSITION_INDEPENDENT_CODE ON
  )
endif()
