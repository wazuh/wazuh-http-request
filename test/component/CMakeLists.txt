project(urlrequest_component_test)

file(GLOB URL_REQUEST_COMPONENT_TEST_SRC *.cpp)

add_executable(urlrequest_component_test ${URL_REQUEST_COMPONENT_TEST_SRC})

target_compile_options(urlrequest_component_test PUBLIC "-fsanitize=address,leak,undefined")
target_link_options(urlrequest_component_test PUBLIC "-fsanitize=address,leak,undefined")

target_link_libraries(urlrequest_component_test urlrequest
    GTest::gmock
    GTest::gtest_main
    urlrequest_test::test)

add_test(NAME urlrequest_component_test
    COMMAND urlrequest_component_test)
