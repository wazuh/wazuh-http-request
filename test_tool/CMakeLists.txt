project(urlrequest_testtool)

file(GLOB URL_REQUEST_SRC *.cpp)

add_executable(urlrequest_testtool ${URL_REQUEST_SRC})
target_link_libraries(urlrequest_testtool urlrequest)
