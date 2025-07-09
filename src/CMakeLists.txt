# -----------------------------------------------------------------------------
# Cryptographic Shim Library (ecgroup)
# -----------------------------------------------------------------------------
add_library(ecgroup
    ecgroup.cpp
    keys.cpp
)

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
# C Wrapper Library for Go Binding
# -----------------------------------------------------------------------------
# This target creates a static library specifically for the C API.
add_library(bbsgs_c_interface SHARED
    bbsgs_c.cpp
)
set_target_properties(bbsgs_c_interface PROPERTIES
  INSTALL_RPATH "$ORIGIN/../lib"
)


# The C wrapper needs to find the public headers.
target_include_directories(bbsgs_c_interface
    PRIVATE
        ${PROJECT_SOURCE_DIR}/include
)

# Link the C wrapper against the main C++ library (bbsgs).
# CMake will automatically handle the transitive dependencies (ecgroup, mcl).
target_link_libraries(bbsgs_c_interface PUBLIC bbsgs)