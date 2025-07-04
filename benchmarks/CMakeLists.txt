# -----------------------------
# Benchmark Executable Definition
# -----------------------------
file(GLOB BENCH_SRC "${CMAKE_CURRENT_SOURCE_DIR}/*.cpp")
add_executable(run_bbsgs_benchmarks ${BENCH_SRC})
target_include_directories(run_bbsgs_benchmarks PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}")

# -----------------------------------------------------------------------------
# Link Libraries
# -----------------------------------------------------------------------------
target_link_libraries(run_bbsgs_benchmarks PRIVATE bbsgs)
