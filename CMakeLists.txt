cmake_minimum_required(VERSION 3.12.4)
project(urlrequest)

get_filename_component(SRC_FOLDER ${PROJECT_SOURCE_DIR}/ ABSOLUTE)

set(CMAKE_CXX_STANDARD 17)

set(CMAKE_CXX_FLAGS "-fPIC")

set(EXTERNAL_DEPS_VERSION "19")

set(RESOURCES_URL "https://packages.wazuh.com/deps/${EXTERNAL_DEPS_VERSION}/libraries/sources")

set(PRECOMPILED_RESOURCES_URL "https://packages.wazuh.com/deps/${EXTERNAL_DEPS_VERSION}/libraries/linux/amd64")

function(check_and_download_dep libname url)
    if(NOT EXISTS ${SRC_FOLDER}/external/${libname})
        message("==============================================")
        message("Downloading ${libname}...")
        file(DOWNLOAD ${url}/${libname}.tar.gz ${SRC_FOLDER}/external/${libname}.tar.gz
            TIMEOUT 60 # seconds
            STATUS DOWNLOAD_STATUS)
        list(GET DOWNLOAD_STATUS 0 STATUS_CODE)
        list(GET DOWNLOAD_STATUS 1 STATUS_MESSAGE)

        if(NOT STATUS_CODE EQUAL 0)
            message(FATAL_ERROR "Error downloading ${libname}: ${STATUS_MESSAGE} (${STATUS_CODE}) .")
        endif(NOT STATUS_CODE EQUAL 0)

        message("Extracting ${libname}.tar.gz")
        execute_process(COMMAND ${CMAKE_COMMAND} -E tar xfz "${SRC_FOLDER}/external/${libname}.tar.gz" WORKING_DIRECTORY ${SRC_FOLDER}/external RESULT_VARIABLE STATUS_VALUE)

        if(NOT STATUS_VALUE EQUAL 0)
            message(FATAL_ERROR "Error extracting ${libname}: ${STATUS_VALUE}.")
        endif(NOT STATUS_VALUE EQUAL 0)

        message("Cleaning ${libname}.tar.gz")
        file(REMOVE ${SRC_FOLDER}/external/${libname}.tar.gz)
    endif()
endfunction(check_and_download_dep)

set(EXTERNAL_RES nlohmann googletest benchmark cpp-httplib)
set(PRECOMPILED_EXTERNAL_RES curl openssl)

foreach(loop_var ${EXTERNAL_RES})
    check_and_download_dep(${loop_var} ${RESOURCES_URL})
endforeach(loop_var)

foreach(loop_var ${PRECOMPILED_EXTERNAL_RES})
    check_and_download_dep(${loop_var} ${PRECOMPILED_RESOURCES_URL})
endforeach(loop_var)

set(BENCHMARK_ENABLE_TESTING "OFF")

include_directories(src/)
include_directories(include/)
include_directories(${SRC_FOLDER}/external/curl/include/curl/)
include_directories(${SRC_FOLDER}/external/nlohmann/)
include_directories(BEFORE PRIVATE shared/)
include_directories(${SRC_FOLDER}/external/openssl/include/)

link_directories(${SRC_FOLDER}/external/openssl/)
link_directories(${SRC_FOLDER}/external/curl/lib/.libs/)

file(GLOB URL_REQUEST_SRC src/*.cpp)

add_library(urlrequest ${URL_REQUEST_SRC})

if(NOT DEFINED CURL_DEP)
    set(CURL_DEP ${SRC_FOLDER}/external/curl/lib/.libs/libcurl.a)
endif(NOT DEFINED CURL_DEP)

target_link_libraries(urlrequest ${CURL_DEP} "-lssl -lcrypto -ldl -lm -lz")

if(${CMAKE_PROJECT_NAME} STREQUAL "urlrequest")
    # Enable testing only if compiling this repository.
    # Always set enable_testing() before add_subdirectory.
    enable_testing()

    add_subdirectory(external/googletest)
    add_subdirectory(external/benchmark)

    add_subdirectory(test_tool)
    add_subdirectory(test)
endif(${CMAKE_PROJECT_NAME} STREQUAL "urlrequest")
