cmake_minimum_required(VERSION 3.12.4)
project(urlrequest)

if(NOT SRC_FOLDER)
    get_filename_component(SRC_FOLDER     ${CMAKE_SOURCE_DIR}/ ABSOLUTE)
endif(NOT SRC_FOLDER)

set(CMAKE_CXX_STANDARD 17)

set(CMAKE_CXX_FLAGS "-fPIC")

if(NOT EXTERNAL_DEPS_VERSION)
    set(EXTERNAL_DEPS_VERSION "19")
endif(NOT EXTERNAL_DEPS_VERSION)

if(NOT RESOURCES_URL)
    set(RESOURCES_URL "https://packages.wazuh.com/deps/${EXTERNAL_DEPS_VERSION}/libraries/sources")
endif(NOT RESOURCES_URL)

if(NOT PRECOMPILED_RESOURCES_URL)
    set(PRECOMPILED_RESOURCES_URL "https://packages.wazuh.com/deps/${EXTERNAL_DEPS_VERSION}/libraries/linux/amd64")
endif(NOT PRECOMPILED_RESOURCES_URL)

if(USE_HTTP)
    string(REPLACE "https://" "http://" RESOURCES_URL ${RESOURCES_URL})
    string(REPLACE "https://" "http://" PRECOMPILED_RESOURCES_URL ${PRECOMPILED_RESOURCES_URL})
endif()

function(check_and_download_dep libname url)
    if(NOT EXISTS ${SRC_FOLDER}/external/${libname})
        message("==============================================")
        message("Downloading ${libname}...")
        file(DOWNLOAD ${url}/${libname}.tar.gz ${SRC_FOLDER}/external/${libname}.tar.gz
             TIMEOUT 60  # seconds
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

foreach(loop_var ${EXTERNAL_RES})
    check_and_download_dep(${loop_var} ${RESOURCES_URL})
endforeach(loop_var)

foreach(loop_var ${PRECOMPILED_EXTERNAL_RES})
    check_and_download_dep(${loop_var} ${PRECOMPILED_RESOURCES_URL})
endforeach(loop_var)

set(BENCHMARK_ENABLE_TESTING "OFF")


set(CMAKE_TOOLCHAIN_FILE ${CMAKE_SOURCE_DIR}/../../vcpkg/scripts/buildsystems/vcpkg.cmake)
set(CMAKE_INCLUDE_PATH ${CMAKE_INCLUDE_PATH} "${CMAKE_SOURCE_DIR}/../../vcpkg/installed/x64-linux/include")
set(CMAKE_LIBRARY_PATH ${CMAKE_LIBRARY_PATH} "${CMAKE_SOURCE_DIR}/../../vcpkg/installed/x64-linux/lib")

include_directories(src/)
include_directories(include/)
include_directories(${SRC_FOLDER}/external/nlohmann/)
include_directories(BEFORE PRIVATE shared/)

file(GLOB URL_REQUEST_SRC src/*.cpp)

add_library(urlrequest ${URL_REQUEST_SRC})

find_package(CURL REQUIRED)
if(CURL_FOUND)
    include_directories(${CURL_INCLUDE_DIRS})
    link_directories(${CURL_LIBRARY_DIRS})
endif()

# Find zlib
find_package(ZLIB REQUIRED)
if(ZLIB_FOUND)
    include_directories(${ZLIB_INCLUDE_DIRS})
    link_directories(${ZLIB_LIBRARY_DIRS})
endif()

find_package(OpenSSL REQUIRED)


target_link_libraries(urlrequest ${ZLIB_LIBRARIES} ${CURL_LIBRARIES} OpenSSL::SSL OpenSSL::Crypto)

# Add include directories for urlrequest
target_include_directories(urlrequest PUBLIC
    ${CURL_LIBRARIES}
    ${SRC_FOLDER}/external/nlohmann/
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)
