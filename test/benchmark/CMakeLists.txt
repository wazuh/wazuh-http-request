project(urlrequest_benchmark_test)

file(GLOB URL_REQUEST_BENCHMARK_TEST_SRC *.cpp)

add_executable(urlrequest_benchmark_test ${URL_REQUEST_BENCHMARK_TEST_SRC})
target_link_libraries(urlrequest_benchmark_test urlrequest
benchmark::benchmark_main)

add_test(NAME urlrequest_benchmark_test
         COMMAND urlrequest_benchmark_test)
