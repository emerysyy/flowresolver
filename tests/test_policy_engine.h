#pragma once

#include <string>
#include <vector>
#include <cstdint>
#include <iostream>
#include <iomanip>
#include <cassert>

namespace test {

// Test case structure
struct TestCase {
    std::string description;
    std::string test_ip;
    uint16_t test_port;
    std::vector<std::string> test_domains;
    uint32_t expected_rule_id;
    bool should_match;
};

// Test statistics
struct TestStats {
    int total = 0;
    int passed = 0;
    int failed = 0;

    void print() const {
        std::cout << "\n========== Test Results ==========\n";
        std::cout << "Total:  " << total << "\n";
        std::cout << "Passed: " << passed << " ("
                  << (total > 0 ? (passed * 100.0 / total) : 0) << "%)\n";
        std::cout << "Failed: " << failed << "\n";
        std::cout << "==================================\n";
    }
};

// Test rule generator
class TestRuleGenerator {
public:
    // Generate IPv4 exact match rules
    static std::vector<std::pair<std::string, std::vector<TestCase>>>
    generateIPv4ExactRules(int count, int start_rule_id);

    // Generate IPv4 CIDR rules
    static std::vector<std::pair<std::string, std::vector<TestCase>>>
    generateIPv4CIDRRules(int count, int start_rule_id);

    // Generate IPv4 range rules
    static std::vector<std::pair<std::string, std::vector<TestCase>>>
    generateIPv4RangeRules(int count, int start_rule_id);

    // Generate IPv6 exact match rules
    static std::vector<std::pair<std::string, std::vector<TestCase>>>
    generateIPv6ExactRules(int count, int start_rule_id);

    // Generate IPv6 CIDR rules
    static std::vector<std::pair<std::string, std::vector<TestCase>>>
    generateIPv6CIDRRules(int count, int start_rule_id);

    // Generate IPv6 range rules
    static std::vector<std::pair<std::string, std::vector<TestCase>>>
    generateIPv6RangeRules(int count, int start_rule_id);

    // Generate domain exact match rules
    static std::vector<std::pair<std::string, std::vector<TestCase>>>
    generateDomainExactRules(int count, int start_rule_id);

    // Generate wildcard domain rules
    static std::vector<std::pair<std::string, std::vector<TestCase>>>
    generateWildcardDomainRules(int count, int start_rule_id);

    // Generate port rules (single, multiple, range)
    static std::vector<std::pair<std::string, std::vector<TestCase>>>
    generatePortRules(int count, int start_rule_id);

    // Generate no-port rules
    static std::vector<std::pair<std::string, std::vector<TestCase>>>
    generateNoPortRules(int count, int start_rule_id);
};

} // namespace test
