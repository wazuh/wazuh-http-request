project(urlrequest_unit_test)

file(GLOB URL_REQUEST_UNIT_TEST_SRC *.cpp)

add_executable(urlrequest_unit_test ${URL_REQUEST_UNIT_TEST_SRC})

target_compile_options(urlrequest_unit_test PUBLIC "-fsanitize=address,leak,undefined")
target_link_options(urlrequest_unit_test PUBLIC "-fsanitize=address,leak,undefined")

target_link_libraries(urlrequest_unit_test urlrequest
    GTest::gmock
    GTest::gtest_main
    urlrequest_test::test)

add_test(NAME urlrequest_unit_test
    COMMAND urlrequest_unit_test)
