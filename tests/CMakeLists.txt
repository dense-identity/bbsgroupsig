# -----------------------------------------------------------------------------
# Test Framework Installation
# -----------------------------------------------------------------------------
FetchContent_Declare(
  Catch2
  GIT_REPOSITORY https://github.com/catchorg/Catch2.git
  GIT_TAG        v3.4.0
)
FetchContent_MakeAvailable(Catch2)


# -----------------------------
# Test Executable Definition (using Catch2)
# -----------------------------
file(GLOB TEST_SRC "${CMAKE_CURRENT_SOURCE_DIR}/*.cpp")
add_executable(run_bbsgs_tests ${TEST_SRC})
target_include_directories(run_bbsgs_tests PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}")

# -----------------------------------------------------------------------------
# Link Libraries
# -----------------------------------------------------------------------------
target_link_libraries(run_bbsgs_tests PRIVATE bbsgs Catch2::Catch2WithMain)
