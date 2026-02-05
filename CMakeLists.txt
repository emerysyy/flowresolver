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
    src/DNS/ip_domain_cache.cpp
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

set(FILTER_SOURCES
    src/Filter/domain_matcher.cpp
    src/Filter/port_matcher.cpp
)

# Library target
add_library(domainresolver
    ${DNS_SOURCES}
    ${PROTOCOL_SOURCES}
    ${RESOLVER_SOURCES}
    ${POLICY_SOURCES}
    ${FILTER_SOURCES}
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
option(BUILD_TESTS "Build test programs" ON)

if(BUILD_TESTS)
    enable_testing()

    # Policy engine test
    add_executable(test_policy_engine
        tests/test_policy_engine.cpp
        src/Filter/domain_matcher.cpp
        src/Filter/port_matcher.cpp
    )
    target_link_libraries(test_policy_engine domainresolver)

    add_test(NAME policy_engine_test COMMAND test_policy_engine)

    # Port filter test
    add_executable(test_port_filter
        tests/test_port_filter.cpp
        src/Filter/port_matcher.cpp
    )
    target_link_libraries(test_port_filter domainresolver)

    add_test(NAME port_filter_test COMMAND test_port_filter)

    # Domain filter test
    add_executable(test_domain_filter
        tests/test_domain_filter.cpp
        src/Filter/domain_matcher.cpp
    )
    target_link_libraries(test_domain_filter domainresolver)

    add_test(NAME domain_filter_test COMMAND test_domain_filter)

    # IP filter test
    add_executable(test_ip_filter
        tests/test_ip_filter.cpp
    )
    target_link_libraries(test_ip_filter domainresolver)

    add_test(NAME ip_filter_test COMMAND test_ip_filter)

    # Benchmark test
    add_executable(test_benchmark
        tests/test_benchmark.cpp
        src/Filter/domain_matcher.cpp
        src/Filter/port_matcher.cpp
    )
    target_link_libraries(test_benchmark domainresolver)

    # Latency test
    add_executable(test_latency
        tests/test_latency.cpp
        src/Filter/domain_matcher.cpp
        src/Filter/port_matcher.cpp
    )
    target_link_libraries(test_latency domainresolver)

    # DNS test (commented out - file not exists)
    # add_executable(test_dns
    #     tests/test_dns.cpp
    # )
    # target_link_libraries(test_dns domainresolver)

    # Protocol parser test (commented out - file not exists)
    # add_executable(test_protocol
    #     tests/test_protocol.cpp
    # )
    # target_link_libraries(test_protocol domainresolver)

    # add_test(NAME dns_test COMMAND test_dns)
    # add_test(NAME protocol_test COMMAND test_protocol)
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
