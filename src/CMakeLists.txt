# -----------------------------------------------------------------------------
# Library Target Definition
# -----------------------------------------------------------------------------
add_library(bbsgs
    bbsgs.cpp
    # Add any other internal .cpp files here
    # e.g., internal_utils.cpp
)

# -----------------------------------------------------------------------------
# Include Directories
# -----------------------------------------------------------------------------
target_include_directories(bbsgs
    PUBLIC
        $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include> # Path when installed
)

# PRIVATE: For internal headers within the 'src' directory. These are needed
# to compile 'bbsgs' itself but are not exposed to consumers of the library.
target_include_directories(bbsgs
    PRIVATE
        . # The current directory ('src')
)

# -----------------------------------------------------------------------------
# Dependencies
# -----------------------------------------------------------------------------
target_link_libraries(bbsgs PRIVATE mcl)
