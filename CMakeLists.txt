cmake_minimum_required(VERSION 3.26)
project(sendEmail)

set(CMAKE_CXX_STANDARD 17)

find_package(OpenSSL REQUIRED)

include_directories(${OPENSSL_INCLUDE_DIR})

add_executable(sendEmail
        example.cpp
        smtp.h)

target_link_libraries(sendEmail OpenSSL::SSL OpenSSL::Crypto)
