cmake_minimum_required(VERSION 3.10)
project(domainresolver VERSION 1.0.0 LANGUAGES CXX)

# C++ Standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Compiler warnings
if(MSVC)
    add_compile_options(/W4)
else()
    add_compile_options(-Wall -Wextra -Wpedantic)
endif()

# Source files
set(DNS_SOURCES
    src/DNS/dns_message.cpp
    src/DNS/dns_cache.cpp
)

set(PROTOCOL_SOURCES
    src/Protocol/http_parser.cpp
    src/Protocol/tls_parser.cpp
    src/Protocol/ftp_parser.cpp
    src/Protocol/ssh_parser.cpp
    src/Protocol/smtp_parser.cpp
    src/Protocol/imap_parser.cpp
    src/Protocol/pop3_parser.cpp
    src/Protocol/smb_parser.cpp
    src/Protocol/tftp_parser.cpp
    src/Protocol/quic_parser.cpp
    src/Protocol/rtp_parser.cpp
    src/Protocol/protocol_detector.cpp
)

set(RESOLVER_SOURCES
    src/Resolver/FlowResolver.cpp
    src/Resolver/flow_cache.cpp
)

set(POLICY_SOURCES
    src/Policy/policy_engine.cpp
)

# Library target
add_library(domainresolver
    ${DNS_SOURCES}
    ${PROTOCOL_SOURCES}
    ${RESOLVER_SOURCES}
    ${POLICY_SOURCES}
)

# Include directories
target_include_directories(domainresolver
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/src>
        $<INSTALL_INTERFACE:include>
)

# Threading support (for dns_cache mutex)
find_package(Threads REQUIRED)
target_link_libraries(domainresolver PUBLIC Threads::Threads)

# Optional: Test target
option(BUILD_TESTS "Build test programs" OFF)

if(BUILD_TESTS)
    enable_testing()

    # DNS test
    add_executable(test_dns
        tests/test_dns.cpp
    )
    target_link_libraries(test_dns domainresolver)

    # Protocol parser test
    add_executable(test_protocol
        tests/test_protocol.cpp
    )
    target_link_libraries(test_protocol domainresolver)

    add_test(NAME dns_test COMMAND test_dns)
    add_test(NAME protocol_test COMMAND test_protocol)
endif()

# Installation rules
install(TARGETS domainresolver
    LIBRARY DESTINATION lib
    ARCHIVE DESTINATION lib
)

install(DIRECTORY src/
    DESTINATION include/domainresolver
    FILES_MATCHING PATTERN "*.hpp"
)
