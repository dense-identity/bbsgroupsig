# -----------------------------------------------------------------------------
# Cryptographic Shim Library
# -----------------------------------------------------------------------------
add_library(ecgroup
    ecgroup.cpp
    keys.cpp
)

# ecgroup needs to know where its own header is
target_include_directories(ecgroup
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
        $<INSTALL_INTERFACE:include>
)

# Link ecgroup against its dependency, mcl
target_link_libraries(ecgroup PRIVATE mcl)


# -----------------------------------------------------------------------------
# Main Library Target Definition
# -----------------------------------------------------------------------------
add_library(bbsgs
    bbsgs.cpp
    keygen.cpp
    helpers.cpp
    signature.cpp
)

# PUBLIC includes are for consumers of the bbsgs library
target_include_directories(bbsgs
    PUBLIC
        $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>
)

# -----------------------------------------------------------------------------
# Link bbsgs against its dependencies
# -----------------------------------------------------------------------------
# bbsgs now depends on your new ecgroup library
target_link_libraries(bbsgs PRIVATE ecgroup)