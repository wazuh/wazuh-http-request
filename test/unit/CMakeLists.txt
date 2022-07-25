cmake_minimum_required(VERSION 3.12.4)
project(urlrequest_unit_test)

file(GLOB URL_REQUEST_UNIT_TEST_SRC *.cpp)

add_executable(urlrequest_unit_test ${URL_REQUEST_UNIT_TEST_SRC})
target_link_libraries(urlrequest_unit_test urlrequest
    debug gtestd
    debug gmockd
    debug gtest_maind
    debug gmock_maind
    optimized gtest
    optimized gmock
    optimized gtest_main
    optimized gmock_main)

add_test(NAME urlrequest_unit_test
         COMMAND urlrequest_unit_test)
