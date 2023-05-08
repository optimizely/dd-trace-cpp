add_executable(example hasher.cpp)

target_link_libraries(example dd_trace_cpp-static)

# Here's a version without any tracing.
add_executable(notrace notrace.cpp)

# Here's a simple program that sends the same input over and over.
add_executable(driver driver.cpp)
