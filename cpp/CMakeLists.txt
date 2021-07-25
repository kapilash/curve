cmake_minimum_required (VERSION 3.12)

project(curve VERSION 0.2 LANGUAGES CXX)
configure_file(.editorconfig .editorconfig COPYONLY)

Set(Boost_USE_MULTITHREADED ON)
set(Boost_USE_STATIC_LIBS ON)
FIND_PACKAGE(Boost REQUIRED COMPONENTS  system filesystem unit_test_framework iostreams date_time)
find_package(CURL REQUIRED)
find_package(RapidJSON CONFIG REQUIRED)
FIND_PACKAGE (Threads REQUIRED )
find_package(OpenSSL REQUIRED)
find_package(cityhash CONFIG REQUIRED)
find_package(unofficial-libuv CONFIG REQUIRED)
find_package(glog CONFIG REQUIRED)

if (CMAKE_CXX_COMPILER_ID MATCHES "Clang")
 add_compile_options(-std=c++14 -stdlib=libc++ -O2)
 set(CMAKE_CXX_FLAGS "-Wall -Wextra")
elseif(CMAKE_CXX_COMPILER_ID MATCHES "GNU")
 add_compile_options(-std=c++14 -O2)
 set(CMAKE_CXX_FLAGS "-Wall -Wextra")
endif()

include(GenerateExportHeader)
include_directories(${curve_SOURCE_DIR})

set(SOURCES
   Jwt.cpp
   Curve.h
   AdAuth.cpp
   Http.cpp
   Utils.cpp)


add_library(curve SHARED ${SOURCES})

target_link_libraries(curve PRIVATE OpenSSL::SSL OpenSSL::Crypto)
target_link_libraries(curve PRIVATE ${CURL_LIBRARIES})
target_link_libraries(curve PRIVATE ${Boost_LIBRARIES}  ${CMAKE_THREAD_LIBS_INIT})
target_link_libraries(curve PRIVATE ${Boost_LIBRARIES}  ${CMAKE_THREAD_LIBS_INIT})
target_link_libraries(curve PRIVATE cityhash)
target_link_libraries(curve PRIVATE unofficial::libuv::libuv)
target_link_libraries(curve PRIVATE glog::glog)

install(TARGETS curve LIBRARY DESTINATION lib)

add_executable(hltest Test.cpp)
target_link_libraries(hltest PRIVATE OpenSSL::SSL OpenSSL::Crypto)
target_link_libraries(hltest PRIVATE ${CURL_LIBRARIES})
target_link_libraries(hltest PRIVATE ${Boost_LIBRARIES}  ${CMAKE_THREAD_LIBS_INIT})
target_link_libraries(hltest PRIVATE ${Boost_LIBRARIES}  ${CMAKE_THREAD_LIBS_INIT})
target_link_libraries(hltest PRIVATE cityhash)
target_link_libraries(hltest PRIVATE unofficial::libuv::libuv)
target_link_libraries(hltest PRIVATE glog::glog)
target_link_libraries(hltest PRIVATE curve)
