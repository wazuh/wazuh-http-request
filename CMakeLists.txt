cmake_minimum_required(VERSION 3.12.4)
project(urlrequest)

set(CMAKE_CXX_STANDARD 17)
set(BENCHMARK_ENABLE_TESTING "OFF")

if (${CMAKE_PROJECT_NAME} STREQUAL "urlrequest")
find_package(benchmark CONFIG REQUIRED)
find_package(GTest CONFIG REQUIRED)
find_package(CURL CONFIG REQUIRED)
find_package(nlohmann_json CONFIG REQUIRED)
find_package(httplib CONFIG REQUIRED)
endif (${CMAKE_PROJECT_NAME} STREQUAL "urlrequest")

file(GLOB URL_REQUEST_SRC src/*.cpp)

add_library(urlrequest ${URL_REQUEST_SRC})
target_link_libraries(urlrequest CURL::libcurl)
target_include_directories(urlrequest PUBLIC ${CMAKE_CURRENT_LIST_DIR}/include PRIVATE ${CMAKE_CURRENT_LIST_DIR}/shared)

if (${CMAKE_PROJECT_NAME} STREQUAL "urlrequest")
    # Enable testing only if compiling this repository.
    # Always set enable_testing() before add_subdirectory.
    enable_testing()

    add_library(urlrequest_test INTERFACE)
    target_include_directories(urlrequest_test INTERFACE ${CMAKE_CURRENT_LIST_DIR}/src ${CMAKE_CURRENT_LIST_DIR}/shared)
    add_library(urlrequest_test::test ALIAS urlrequest_test)

    add_subdirectory(test_tool)
    add_subdirectory(test)
endif (${CMAKE_PROJECT_NAME} STREQUAL "urlrequest")
