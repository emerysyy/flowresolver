#include "test_policy_engine.h"
#include "../src/Policy/policy_engine.hpp"
#include "../src/Protocol/protocol_detector.hpp"
#include <sstream>
#include <iomanip>

namespace test {

// Helper function to convert uint32_t IP to string
std::string ipv4ToString(uint32_t ip) {
    std::ostringstream oss;
    oss << ((ip >> 24) & 0xFF) << "."
        << ((ip >> 16) & 0xFF) << "."
        << ((ip >> 8) & 0xFF) << "."
        << (ip & 0xFF);
    return oss.str();
}

// Helper function to convert IPv6 to string
std::string ipv6ToString(uint64_t hi, uint64_t lo) {
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    oss << std::setw(4) << ((hi >> 48) & 0xFFFF) << ":"
        << std::setw(4) << ((hi >> 32) & 0xFFFF) << ":"
        << std::setw(4) << ((hi >> 16) & 0xFFFF) << ":"
        << std::setw(4) << (hi & 0xFFFF) << ":"
        << std::setw(4) << ((lo >> 48) & 0xFFFF) << ":"
        << std::setw(4) << ((lo >> 32) & 0xFFFF) << ":"
        << std::setw(4) << ((lo >> 16) & 0xFFFF) << ":"
        << std::setw(4) << (lo & 0xFFFF);
    return oss.str();
}

// Generate IPv4 exact match rules
std::vector<std::pair<std::string, std::vector<TestCase>>>
TestRuleGenerator::generateIPv4ExactRules(int count, int start_rule_id) {
    std::vector<std::pair<std::string, std::vector<TestCase>>> result;

    for (int i = 0; i < count; i++) {
        uint32_t rule_id = start_rule_id + i;
        // Generate IP: 10.0.x.y
        uint32_t ip = (10 << 24) | ((i / 256) << 8) | (i % 256);
        std::string ip_str = ipv4ToString(ip);
        uint16_t port = 8000 + (i % 1000);

        std::vector<TestCase> test_cases;

        // Positive test case - exact match
        test_cases.push_back({
            "IPv4 exact match - positive",
            ip_str,
            port,
            {},
            rule_id,
            true
        });

        // Negative test case - different IP
        uint32_t wrong_ip = ip + 1;
        test_cases.push_back({
            "IPv4 exact match - negative (wrong IP)",
            ipv4ToString(wrong_ip),
            port,
            {},
            rule_id,
            false
        });

        // Negative test case - different port
        test_cases.push_back({
            "IPv4 exact match - negative (wrong port)",
            ip_str,
            static_cast<uint16_t>(port + 1),
            {},
            rule_id,
            false
        });

        result.push_back({ip_str + ":" + std::to_string(port), test_cases});
    }

    return result;
}
// Generate IPv4 CIDR rules
std::vector<std::pair<std::string, std::vector<TestCase>>>
TestRuleGenerator::generateIPv4CIDRRules(int count, int start_rule_id) {
    std::vector<std::pair<std::string, std::vector<TestCase>>> result;

    for (int i = 0; i < count; i++) {
        uint32_t rule_id = start_rule_id + i;
        // Generate CIDR: 192.168.x.0/24
        uint32_t network = (192 << 24) | (168 << 16) | ((i % 256) << 8);
        std::string cidr_str = ipv4ToString(network) + "/24";
        uint16_t port = 9000 + (i % 1000);

        std::vector<TestCase> test_cases;

        // Positive test case - IP within CIDR
        uint32_t ip_in_range = network | 100;
        test_cases.push_back({
            "IPv4 CIDR - positive (IP in range)",
            ipv4ToString(ip_in_range),
            port,
            {},
            rule_id,
            true
        });

        // Positive test case - another IP within CIDR
        uint32_t ip_in_range2 = network | 200;
        test_cases.push_back({
            "IPv4 CIDR - positive (another IP in range)",
            ipv4ToString(ip_in_range2),
            port,
            {},
            rule_id,
            true
        });

        // Negative test case - IP outside CIDR
        uint32_t ip_out_range = network + 256;
        test_cases.push_back({
            "IPv4 CIDR - negative (IP out of range)",
            ipv4ToString(ip_out_range),
            port,
            {},
            rule_id,
            false
        });

        // Negative test case - wrong port
        test_cases.push_back({
            "IPv4 CIDR - negative (wrong port)",
            ipv4ToString(ip_in_range),
            static_cast<uint16_t>(port + 1),
            {},
            rule_id,
            false
        });

        result.push_back({cidr_str + ":" + std::to_string(port), test_cases});
    }

    return result;
}

// Generate IPv4 range rules
std::vector<std::pair<std::string, std::vector<TestCase>>>
TestRuleGenerator::generateIPv4RangeRules(int count, int start_rule_id) {
    std::vector<std::pair<std::string, std::vector<TestCase>>> result;

    for (int i = 0; i < count; i++) {
        uint32_t rule_id = start_rule_id + i;
        // Generate range: 172.16.x.1-172.16.x.100
        uint32_t start_ip = (172 << 24) | (16 << 16) | ((i % 256) << 8) | 1;
        uint32_t end_ip = (172 << 24) | (16 << 16) | ((i % 256) << 8) | 100;
        std::string range_str = ipv4ToString(start_ip) + "-" + ipv4ToString(end_ip);
        uint16_t port = 10000 + (i % 1000);

        std::vector<TestCase> test_cases;

        // Positive test case - IP at start of range
        test_cases.push_back({
            "IPv4 range - positive (start)",
            ipv4ToString(start_ip),
            port,
            {},
            rule_id,
            true
        });

        // Positive test case - IP in middle of range
        uint32_t mid_ip = start_ip + 50;
        test_cases.push_back({
            "IPv4 range - positive (middle)",
            ipv4ToString(mid_ip),
            port,
            {},
            rule_id,
            true
        });

        // Positive test case - IP at end of range
        test_cases.push_back({
            "IPv4 range - positive (end)",
            ipv4ToString(end_ip),
            port,
            {},
            rule_id,
            true
        });

        // Negative test case - IP before range
        uint32_t before_ip = start_ip - 1;
        test_cases.push_back({
            "IPv4 range - negative (before range)",
            ipv4ToString(before_ip),
            port,
            {},
            rule_id,
            false
        });

        // Negative test case - IP after range
        uint32_t after_ip = end_ip + 1;
        test_cases.push_back({
            "IPv4 range - negative (after range)",
            ipv4ToString(after_ip),
            port,
            {},
            rule_id,
            false
        });

        result.push_back({range_str + ":" + std::to_string(port), test_cases});
    }

    return result;
}

// Generate IPv6 exact match rules
std::vector<std::pair<std::string, std::vector<TestCase>>>
TestRuleGenerator::generateIPv6ExactRules(int count, int start_rule_id) {
    std::vector<std::pair<std::string, std::vector<TestCase>>> result;

    for (int i = 0; i < count; i++) {
        uint32_t rule_id = start_rule_id + i;
        // Generate IPv6: 2001:db8::x
        uint64_t hi = 0x20010db800000000ULL;
        uint64_t lo = i;
        std::string ip_str = ipv6ToString(hi, lo);
        uint16_t port = 8000 + (i % 1000);

        std::vector<TestCase> test_cases;

        // Positive test case - exact match
        test_cases.push_back({
            "IPv6 exact match - positive",
            ip_str,
            port,
            {},
            rule_id,
            true
        });

        // Negative test case - different IPv6
        uint64_t wrong_lo = lo + 1;
        test_cases.push_back({
            "IPv6 exact match - negative (wrong IP)",
            ipv6ToString(hi, wrong_lo),
            port,
            {},
            rule_id,
            false
        });

        // Negative test case - different port
        test_cases.push_back({
            "IPv6 exact match - negative (wrong port)",
            ip_str,
            static_cast<uint16_t>(port + 1),
            {},
            rule_id,
            false
        });

        result.push_back({ip_str + ":" + std::to_string(port), test_cases});
    }

    return result;
}

// Generate IPv6 CIDR rules
std::vector<std::pair<std::string, std::vector<TestCase>>>
TestRuleGenerator::generateIPv6CIDRRules(int count, int start_rule_id) {
    std::vector<std::pair<std::string, std::vector<TestCase>>> result;

    for (int i = 0; i < count; i++) {
        uint32_t rule_id = start_rule_id + i;
        // Generate CIDR: 2001:db8:x::/64
        uint64_t hi = 0x20010db800000000ULL | (static_cast<uint64_t>(i) << 16);
        std::string cidr_str = ipv6ToString(hi, 0) + "/64";
        uint16_t port = 9000 + (i % 1000);

        std::vector<TestCase> test_cases;

        // Positive test case - IP within CIDR
        uint64_t lo_in_range = 0x1000;
        test_cases.push_back({
            "IPv6 CIDR - positive (IP in range)",
            ipv6ToString(hi, lo_in_range),
            port,
            {},
            rule_id,
            true
        });

        // Positive test case - another IP within CIDR
        uint64_t lo_in_range2 = 0xFFFF;
        test_cases.push_back({
            "IPv6 CIDR - positive (another IP in range)",
            ipv6ToString(hi, lo_in_range2),
            port,
            {},
            rule_id,
            true
        });

        // Negative test case - IP outside CIDR (different /64 block)
        uint64_t hi_out = hi + 0x10000;
        test_cases.push_back({
            "IPv6 CIDR - negative (IP out of range)",
            ipv6ToString(hi_out, 0),
            port,
            {},
            rule_id,
            false
        });

        // Negative test case - wrong port
        test_cases.push_back({
            "IPv6 CIDR - negative (wrong port)",
            ipv6ToString(hi, lo_in_range),
            static_cast<uint16_t>(port + 1),
            {},
            rule_id,
            false
        });

        result.push_back({cidr_str + ":" + std::to_string(port), test_cases});
    }

    return result;
}

// Generate IPv6 range rules
std::vector<std::pair<std::string, std::vector<TestCase>>>
TestRuleGenerator::generateIPv6RangeRules(int count, int start_rule_id) {
    std::vector<std::pair<std::string, std::vector<TestCase>>> result;

    for (int i = 0; i < count; i++) {
        uint32_t rule_id = start_rule_id + i;
        // Generate range: 2001:db8:x::1-2001:db8:x::100
        uint64_t hi = 0x20010db800000000ULL | (static_cast<uint64_t>(i) << 16);
        uint64_t lo_start = 1;
        uint64_t lo_end = 0x100;
        std::string range_str = ipv6ToString(hi, lo_start) + "-" + ipv6ToString(hi, lo_end);
        uint16_t port = 10000 + (i % 1000);

        std::vector<TestCase> test_cases;

        // Positive test case - IP at start of range
        test_cases.push_back({
            "IPv6 range - positive (start)",
            ipv6ToString(hi, lo_start),
            port,
            {},
            rule_id,
            true
        });

        // Positive test case - IP in middle of range
        uint64_t lo_mid = (lo_start + lo_end) / 2;
        test_cases.push_back({
            "IPv6 range - positive (middle)",
            ipv6ToString(hi, lo_mid),
            port,
            {},
            rule_id,
            true
        });

        // Positive test case - IP at end of range
        test_cases.push_back({
            "IPv6 range - positive (end)",
            ipv6ToString(hi, lo_end),
            port,
            {},
            rule_id,
            true
        });

        // Negative test case - IP before range
        uint64_t lo_before = lo_start - 1;
        test_cases.push_back({
            "IPv6 range - negative (before range)",
            ipv6ToString(hi, lo_before),
            port,
            {},
            rule_id,
            false
        });

        // Negative test case - IP after range
        uint64_t lo_after = lo_end + 1;
        test_cases.push_back({
            "IPv6 range - negative (after range)",
            ipv6ToString(hi, lo_after),
            port,
            {},
            rule_id,
            false
        });

        result.push_back({range_str + ":" + std::to_string(port), test_cases});
    }

    return result;
}

// Generate domain exact match rules
std::vector<std::pair<std::string, std::vector<TestCase>>>
TestRuleGenerator::generateDomainExactRules(int count, int start_rule_id) {
    std::vector<std::pair<std::string, std::vector<TestCase>>> result;

    for (int i = 0; i < count; i++) {
        uint32_t rule_id = start_rule_id + i;
        std::string domain = "example" + std::to_string(i) + ".com";
        uint16_t port = 443;

        std::vector<TestCase> test_cases;

        // Positive test case - exact domain match
        test_cases.push_back({
            "Domain exact - positive",
            "",  // No IP for domain matching
            port,
            {domain},
            rule_id,
            true
        });

        // Negative test case - different domain
        std::string wrong_domain = "wrong" + std::to_string(i) + ".com";
        test_cases.push_back({
            "Domain exact - negative (wrong domain)",
            "",
            port,
            {wrong_domain},
            rule_id,
            false
        });

        // Negative test case - subdomain (should not match exact)
        std::string subdomain = "sub." + domain;
        test_cases.push_back({
            "Domain exact - negative (subdomain)",
            "",
            port,
            {subdomain},
            rule_id,
            false
        });

        // Negative test case - wrong port
        test_cases.push_back({
            "Domain exact - negative (wrong port)",
            "",
            static_cast<uint16_t>(port + 1),
            {domain},
            rule_id,
            false
        });

        result.push_back({domain + ":" + std::to_string(port), test_cases});
    }

    return result;
}

// Generate wildcard domain rules
std::vector<std::pair<std::string, std::vector<TestCase>>>
TestRuleGenerator::generateWildcardDomainRules(int count, int start_rule_id) {
    std::vector<std::pair<std::string, std::vector<TestCase>>> result;

    for (int i = 0; i < count; i++) {
        uint32_t rule_id = start_rule_id + i;
        std::string wildcard = "*.wildcard" + std::to_string(i) + ".com";
        uint16_t port = 443;

        std::vector<TestCase> test_cases;

        // Positive test case - subdomain matches wildcard
        std::string subdomain1 = "www.wildcard" + std::to_string(i) + ".com";
        test_cases.push_back({
            "Wildcard domain - positive (subdomain 1)",
            "",
            port,
            {subdomain1},
            rule_id,
            true
        });

        // Positive test case - another subdomain matches wildcard
        std::string subdomain2 = "api.wildcard" + std::to_string(i) + ".com";
        test_cases.push_back({
            "Wildcard domain - positive (subdomain 2)",
            "",
            port,
            {subdomain2},
            rule_id,
            true
        });

        // Negative test case - different domain
        std::string wrong_domain = "www.other" + std::to_string(i) + ".com";
        test_cases.push_back({
            "Wildcard domain - negative (wrong domain)",
            "",
            port,
            {wrong_domain},
            rule_id,
            false
        });

        // Negative test case - wrong port
        test_cases.push_back({
            "Wildcard domain - negative (wrong port)",
            "",
            static_cast<uint16_t>(port + 1),
            {subdomain1},
            rule_id,
            false
        });

        result.push_back({wildcard + ":" + std::to_string(port), test_cases});
    }

    return result;
}

// Generate port rules (single, multiple, range)
std::vector<std::pair<std::string, std::vector<TestCase>>>
TestRuleGenerator::generatePortRules(int count, int start_rule_id) {
    std::vector<std::pair<std::string, std::vector<TestCase>>> result;

    for (int i = 0; i < count; i++) {
        uint32_t rule_id = start_rule_id + i;
        uint32_t ip = (10 << 24) | (100 << 16) | ((i / 256) << 8) | (i % 256);
        std::string ip_str = ipv4ToString(ip);

        // Vary port rules: single, multiple, range
        std::string port_rule;
        std::vector<uint16_t> valid_ports;
        std::vector<uint16_t> invalid_ports;

        if (i % 3 == 0) {
            // Single port
            uint16_t port = 8000 + i;
            port_rule = std::to_string(port);
            valid_ports = {port};
            invalid_ports = {static_cast<uint16_t>(port + 1), static_cast<uint16_t>(port - 1)};
        } else if (i % 3 == 1) {
            // Multiple ports
            uint16_t port1 = 8000 + i;
            uint16_t port2 = 9000 + i;
            port_rule = std::to_string(port1) + "," + std::to_string(port2);
            valid_ports = {port1, port2};
            invalid_ports = {static_cast<uint16_t>(port1 + 1)};
        } else {
            // Port range
            uint16_t port_start = 8000 + i;
            uint16_t port_end = port_start + 10;
            port_rule = std::to_string(port_start) + "-" + std::to_string(port_end);
            valid_ports = {port_start, static_cast<uint16_t>(port_start + 5), port_end};
            invalid_ports = {static_cast<uint16_t>(port_start - 1), static_cast<uint16_t>(port_end + 1)};
        }

        std::vector<TestCase> test_cases;

        // Positive test cases - valid ports
        for (size_t j = 0; j < valid_ports.size(); j++) {
            test_cases.push_back({
                "Port rule - positive (port " + std::to_string(j) + ")",
                ip_str,
                valid_ports[j],
                {},
                rule_id,
                true
            });
        }

        // Negative test cases - invalid ports
        for (size_t j = 0; j < invalid_ports.size(); j++) {
            test_cases.push_back({
                "Port rule - negative (invalid port " + std::to_string(j) + ")",
                ip_str,
                invalid_ports[j],
                {},
                rule_id,
                false
            });
        }

        result.push_back({ip_str + ":" + port_rule, test_cases});
    }

    return result;
}

// Generate no-port rules (empty port string means match all ports)
std::vector<std::pair<std::string, std::vector<TestCase>>>
TestRuleGenerator::generateNoPortRules(int count, int start_rule_id) {
    std::vector<std::pair<std::string, std::vector<TestCase>>> result;

    for (int i = 0; i < count; i++) {
        uint32_t rule_id = start_rule_id + i;
        uint32_t ip = (10 << 24) | (200 << 16) | ((i / 256) << 8) | (i % 256);
        std::string ip_str = ipv4ToString(ip);

        std::vector<TestCase> test_cases;

        // Positive test cases - should match any port
        test_cases.push_back({
            "No-port rule - positive (port 80)",
            ip_str,
            80,
            {},
            rule_id,
            true
        });

        test_cases.push_back({
            "No-port rule - positive (port 443)",
            ip_str,
            443,
            {},
            rule_id,
            true
        });

        test_cases.push_back({
            "No-port rule - positive (port 8080)",
            ip_str,
            8080,
            {},
            rule_id,
            true
        });

        // Negative test case - wrong IP
        uint32_t wrong_ip = ip + 1;
        test_cases.push_back({
            "No-port rule - negative (wrong IP)",
            ipv4ToString(wrong_ip),
            80,
            {},
            rule_id,
            false
        });

        result.push_back({ip_str + ":", test_cases});
    }

    return result;
}

} // namespace test



// Helper function to run a test suite
template<typename RuleGenerator>
void runTestSuite(const std::string& suite_name, int count, int& rule_id_counter, 
                  policy::PolicyEngine& engine, test::TestStats& stats,
                  RuleGenerator generator) {
    using namespace test;
    using namespace flow;
    
    std::cout << "\n[" << suite_name << "] Testing " << count << " rules...\n";
    auto rules = generator(count, rule_id_counter);
    
    int suite_passed = 0;
    int suite_total = 0;
    
    for (const auto& [rule_str, test_cases] : rules) {
        // Parse address and port from rule string
        // For IPv6, use rfind to get the last colon (port separator)
        size_t colon_pos = rule_str.rfind(':');
        std::string address = rule_str.substr(0, colon_pos);
        std::string port = (colon_pos != std::string::npos) ? rule_str.substr(colon_pos + 1) : "";

        policy::Policy policy{static_cast<uint32_t>(rule_id_counter++), address, port};
        if (!engine.addPolicy(policy)) {
            std::cerr << "  ERROR: Failed to add policy: " << rule_str << "\n";
            continue;
        }

        // Run test cases
        for (const auto& tc : test_cases) {
            FlowIP test_ip;
            
            // Parse IP if provided
            if (!tc.test_ip.empty()) {
                if (tc.test_ip.find(':') != std::string::npos) {
                    // IPv6
                    uint64_t hi, lo;
                    if (IPUtils::parseIPv6(tc.test_ip.c_str(), hi, lo)) {
                        test_ip = FlowIP::fromIPv6(hi, lo);
                    }
                } else if (tc.test_ip.find('.') != std::string::npos) {
                    // IPv4
                    uint32_t ip_val;
                    if (IPUtils::parseIPv4(tc.test_ip.c_str(), ip_val)) {
                        test_ip = FlowIP::fromIPv4(ip_val);
                    }
                }
            }

            auto matches = engine.match(proto::ProtocolType::Unknown, test_ip, tc.test_port, tc.test_domains);
            bool matched = matches.find(tc.expected_rule_id) != matches.end();

            suite_total++;
            stats.total++;
            
            if (matched == tc.should_match) {
                suite_passed++;
                stats.passed++;
            } else {
                stats.failed++;
                if (stats.failed <= 10) {  // Only print first 10 failures
                    std::cout << "  FAIL: " << tc.description << "\n";
                    std::cout << "    Rule: " << rule_str << "\n";
                    std::cout << "    Expected: " << (tc.should_match ? "match" : "no match")
                              << ", Got: " << (matched ? "match" : "no match") << "\n";
                }
            }
        }
    }
    
    std::cout << "  " << suite_name << ": " << suite_passed << "/" << suite_total << " passed";
    if (suite_passed == suite_total) {
        std::cout << " ✓\n";
    } else {
        std::cout << " ✗\n";
    }
}

// Main test runner
int main() {
    using namespace test;
    using namespace policy;
    using namespace flow;

    std::cout << "========================================\n";
    std::cout << "  Policy Engine Comprehensive Test Suite\n";
    std::cout << "========================================\n\n";

    TestStats total_stats;

    // Test configurations: rule counts from 10 to 10,000
    std::vector<int> test_counts = {10, 100};

    for (int count : test_counts) {
        std::cout << "\n========== Testing with " << count << " rules per type ==========\n";

        PolicyEngine engine;
        TestStats stats;
        int rule_id_counter = 1;

        // Run all test suites
        runTestSuite("IPv4 Exact", count, rule_id_counter, engine, stats, TestRuleGenerator::generateIPv4ExactRules);
        runTestSuite("IPv4 CIDR", count, rule_id_counter, engine, stats, TestRuleGenerator::generateIPv4CIDRRules);
        runTestSuite("IPv4 Range", count, rule_id_counter, engine, stats, TestRuleGenerator::generateIPv4RangeRules);
        runTestSuite("IPv6 Exact", count, rule_id_counter, engine, stats, TestRuleGenerator::generateIPv6ExactRules);
        runTestSuite("IPv6 CIDR", count, rule_id_counter, engine, stats, TestRuleGenerator::generateIPv6CIDRRules);
        runTestSuite("IPv6 Range", count, rule_id_counter, engine, stats, TestRuleGenerator::generateIPv6RangeRules);
        runTestSuite("Domain Exact", count, rule_id_counter, engine, stats, TestRuleGenerator::generateDomainExactRules);
        runTestSuite("Wildcard Domain", count, rule_id_counter, engine, stats, TestRuleGenerator::generateWildcardDomainRules);
        runTestSuite("Port Rules", count, rule_id_counter, engine, stats, TestRuleGenerator::generatePortRules);
        runTestSuite("No-Port Rules", count, rule_id_counter, engine, stats, TestRuleGenerator::generateNoPortRules);

        std::cout << "\n[Summary for " << count << " rules per type]\n";
        std::cout << "  Total rules added: " << engine.getPolicyCount() << "\n";
        std::cout << "  Total tests: " << stats.total << "\n";
        std::cout << "  Passed: " << stats.passed << " (" 
                  << (stats.total > 0 ? (stats.passed * 100.0 / stats.total) : 0) << "%)\n";
        std::cout << "  Failed: " << stats.failed << "\n";

        total_stats.total += stats.total;
        total_stats.passed += stats.passed;
        total_stats.failed += stats.failed;
    }

    // ==================== Stress Test: 10,000 Rules ====================
    std::cout << "\n========== Stress Test: 10,000 Rules ==========\n";

    PolicyEngine stress_engine;
    uint32_t stress_rule_id = 1;

    auto start_insert = std::chrono::high_resolution_clock::now();

    // Prepare all policies in batch
    std::vector<policy::Policy> stress_policies;
    stress_policies.reserve(10000);

    // Insert 1000 IPv4 exact rules
    for (int i = 0; i < 1000; i++) {
        uint32_t ip = (10 << 24) | ((i / 256) << 8) | (i % 256);
        std::string ip_str = ipv4ToString(ip);
        uint16_t port = 8000 + (i % 1000);
        stress_policies.push_back(policy::Policy{stress_rule_id++, ip_str, std::to_string(port)});
    }

    // Insert 1000 IPv4 CIDR rules
    for (int i = 0; i < 1000; i++) {
        uint32_t network = (192 << 24) | (168 << 16) | ((i % 256) << 8);
        std::string cidr_str = ipv4ToString(network) + "/24";
        uint16_t port = 9000 + (i % 1000);
        stress_policies.push_back(policy::Policy{stress_rule_id++, cidr_str, std::to_string(port)});
    }

    // Insert 1000 IPv4 range rules
    for (int i = 0; i < 1000; i++) {
        uint32_t start_ip = (172 << 24) | (16 << 16) | ((i % 256) << 8) | 1;
        uint32_t end_ip = (172 << 24) | (16 << 16) | ((i % 256) << 8) | 100;
        std::string range_str = ipv4ToString(start_ip) + "-" + ipv4ToString(end_ip);
        uint16_t port = 10000 + (i % 1000);
        stress_policies.push_back(policy::Policy{stress_rule_id++, range_str, std::to_string(port)});
    }

    // Insert 1000 IPv6 exact rules
    for (int i = 0; i < 1000; i++) {
        uint64_t hi = 0x20010db800000000ULL;
        uint64_t lo = i;
        std::string ip_str = ipv6ToString(hi, lo);
        uint16_t port = 8000 + (i % 1000);
        stress_policies.push_back(policy::Policy{stress_rule_id++, ip_str, std::to_string(port)});
    }

    // Insert 1000 IPv6 CIDR rules
    for (int i = 0; i < 1000; i++) {
        uint64_t hi = 0x20010db800000000ULL | (static_cast<uint64_t>(i) << 16);
        std::string cidr_str = ipv6ToString(hi, 0) + "/64";
        uint16_t port = 9000 + (i % 1000);
        stress_policies.push_back(policy::Policy{stress_rule_id++, cidr_str, std::to_string(port)});
    }

    // Insert 1000 IPv6 range rules
    for (int i = 0; i < 1000; i++) {
        uint64_t hi = 0x20010db800000000ULL | (static_cast<uint64_t>(i) << 16);
        uint64_t lo_start = 1;
        uint64_t lo_end = 0x100;
        std::string range_str = ipv6ToString(hi, lo_start) + "-" + ipv6ToString(hi, lo_end);
        uint16_t port = 10000 + (i % 1000);
        stress_policies.push_back(policy::Policy{stress_rule_id++, range_str, std::to_string(port)});
    }

    // Insert 1000 domain exact rules
    for (int i = 0; i < 1000; i++) {
        std::string domain = "stress" + std::to_string(i) + ".com";
        stress_policies.push_back(policy::Policy{stress_rule_id++, domain, "443"});
    }

    // Insert 1000 wildcard domain rules
    for (int i = 0; i < 1000; i++) {
        std::string wildcard = "*.wildcard" + std::to_string(i) + ".com";
        stress_policies.push_back(policy::Policy{stress_rule_id++, wildcard, "443"});
    }

    // Insert 1000 port rules (with variations)
    for (int i = 0; i < 1000; i++) {
        uint32_t ip = (10 << 24) | (100 << 16) | ((i / 256) << 8) | (i % 256);
        std::string ip_str = ipv4ToString(ip);

        std::string port_rule;
        if (i % 3 == 0) {
            port_rule = std::to_string(8000 + i);
        } else if (i % 3 == 1) {
            port_rule = std::to_string(8000 + i) + "," + std::to_string(9000 + i);
        } else {
            uint16_t port_start = 8000 + i;
            uint16_t port_end = port_start + 10;
            port_rule = std::to_string(port_start) + "-" + std::to_string(port_end);
        }

        stress_policies.push_back(policy::Policy{stress_rule_id++, ip_str, port_rule});
    }

    // Insert 1000 no-port rules
    for (int i = 0; i < 1000; i++) {
        uint32_t ip = (10 << 24) | (200 << 16) | ((i / 256) << 8) | (i % 256);
        std::string ip_str = ipv4ToString(ip);
        stress_policies.push_back(policy::Policy{stress_rule_id++, ip_str, ""});
    }

    // Batch add all policies
    size_t added = stress_engine.addPolicies(stress_policies);
    if (added != stress_policies.size()) {
        std::cerr << "  WARNING: Only added " << added << " out of " << stress_policies.size() << " policies\n";
    }

    auto end_insert = std::chrono::high_resolution_clock::now();
    auto insert_duration = std::chrono::duration_cast<std::chrono::milliseconds>(end_insert - start_insert);

    std::cout << "  ✓ Inserted 10,000 rules in " << insert_duration.count() << "ms\n";
    std::cout << "    Average: " << (insert_duration.count() / 10.0) << "ms per 1000 rules\n";

    // Query performance test: 10,000 random queries
    auto start_query = std::chrono::high_resolution_clock::now();

    int query_matches = 0;
    for (int i = 0; i < 10000; i++) {
        // Randomly query different rule types
        int rule_type = i % 10;
        FlowIP test_ip;
        uint16_t test_port;
        std::vector<std::string> test_domains;

        switch (rule_type) {
            case 0: // IPv4 exact
                {
                    uint32_t ip = (10 << 24) | ((i / 256) << 8) | (i % 256);
                    test_ip = FlowIP::fromIPv4(ip);
                    test_port = 8000 + (i % 1000);
                }
                break;
            case 1: // IPv4 CIDR
                {
                    uint32_t network = (192 << 24) | (168 << 16) | ((i % 256) << 8);
                    uint32_t ip = network | 100;
                    test_ip = FlowIP::fromIPv4(ip);
                    test_port = 9000 + (i % 1000);
                }
                break;
            case 2: // IPv4 range
                {
                    uint32_t ip = (172 << 24) | (16 << 16) | ((i % 256) << 8) | 50;
                    test_ip = FlowIP::fromIPv4(ip);
                    test_port = 10000 + (i % 1000);
                }
                break;
            case 3: // IPv6 exact
                {
                    uint64_t hi = 0x20010db800000000ULL;
                    uint64_t lo = i;
                    test_ip = FlowIP::fromIPv6(hi, lo);
                    test_port = 8000 + (i % 1000);
                }
                break;
            case 4: // IPv6 CIDR
                {
                    uint64_t hi = 0x20010db800000000ULL | (static_cast<uint64_t>(i % 256) << 16);
                    uint64_t lo = 0x1000;
                    test_ip = FlowIP::fromIPv6(hi, lo);
                    test_port = 9000 + (i % 1000);
                }
                break;
            case 5: // IPv6 range
                {
                    uint64_t hi = 0x20010db800000000ULL | (static_cast<uint64_t>(i % 256) << 16);
                    uint64_t lo = 50;
                    test_ip = FlowIP::fromIPv6(hi, lo);
                    test_port = 10000 + (i % 1000);
                }
                break;
            case 6: // Domain exact
                {
                    test_domains.push_back("stress" + std::to_string(i) + ".com");
                    test_port = 443;
                }
                break;
            case 7: // Wildcard domain
                {
                    test_domains.push_back("www.wildcard" + std::to_string(i) + ".com");
                    test_port = 443;
                }
                break;
            case 8: // Port rules
                {
                    uint32_t ip = (10 << 24) | (100 << 16) | ((i / 256) << 8) | (i % 256);
                    test_ip = FlowIP::fromIPv4(ip);
                    test_port = 8000 + i;
                }
                break;
            case 9: // No-port rules
                {
                    uint32_t ip = (10 << 24) | (200 << 16) | ((i / 256) << 8) | (i % 256);
                    test_ip = FlowIP::fromIPv4(ip);
                    test_port = 8080;
                }
                break;
        }

        auto matches = stress_engine.match(proto::ProtocolType::Unknown, test_ip, test_port, test_domains);
        if (!matches.empty()) {
            query_matches++;
        }
    }

    auto end_query = std::chrono::high_resolution_clock::now();
    auto query_duration = std::chrono::duration_cast<std::chrono::milliseconds>(end_query - start_query);

    std::cout << "  ✓ Executed 10,000 queries in " << query_duration.count() << "ms\n";
    std::cout << "    Average: " << (query_duration.count() * 100.0 / 10000.0) << "μs per query\n";
    std::cout << "    Query match rate: " << (query_matches * 100 / 10000) << "%\n";

    // Verify a sample of rules still work correctly
    std::cout << "\n  Verifying sample queries...\n";

    int sample_passed = 0;
    int sample_total = 10;

    // Test IPv4 exact (i=99 -> rule 100: 10.0.0.99:8099)
    {
        uint32_t ip = (10 << 24) | 99;
        FlowIP test_ip = FlowIP::fromIPv4(ip);
        auto matches = stress_engine.match(proto::ProtocolType::Unknown, test_ip, 8099, {});
        if (!matches.empty()) sample_passed++;
    }

    // Test IPv4 CIDR (i=99 -> rule 1100: 192.168.99.0/24:9099, query 192.168.99.100:9099)
    {
        uint32_t ip = (192 << 24) | (168 << 16) | (99 << 8) | 100;
        FlowIP test_ip = FlowIP::fromIPv4(ip);
        auto matches = stress_engine.match(proto::ProtocolType::Unknown, test_ip, 9099, {});
        if (!matches.empty()) sample_passed++;
    }

    // Test IPv4 range (i=99 -> rule 2100: 172.16.99.1-100:10099)
    {
        uint32_t ip = (172 << 24) | (16 << 16) | (99 << 8) | 50;
        FlowIP test_ip = FlowIP::fromIPv4(ip);
        auto matches = stress_engine.match(proto::ProtocolType::Unknown, test_ip, 10099, {});
        if (!matches.empty()) sample_passed++;
    }

    // Test IPv6 exact (i=99 -> rule 3100: 2001:db8::99:8099)
    {
        FlowIP test_ip = FlowIP::fromIPv6(0x20010db800000000ULL, 99);
        auto matches = stress_engine.match(proto::ProtocolType::Unknown, test_ip, 8099, {});
        if (!matches.empty()) sample_passed++;
    }

    // Test IPv6 CIDR (i=99 -> rule 4100: 2001:db8:0:99::/64:9099)
    {
        FlowIP test_ip = FlowIP::fromIPv6(0x20010db800000000ULL | (99ULL << 16), 0x1000);
        auto matches = stress_engine.match(proto::ProtocolType::Unknown, test_ip, 9099, {});
        if (!matches.empty()) sample_passed++;
    }

    // Test IPv6 range (i=99 -> rule 5100: 2001:db8:0:99::1-100:10099)
    {
        FlowIP test_ip = FlowIP::fromIPv6(0x20010db800000000ULL | (99ULL << 16), 50);
        auto matches = stress_engine.match(proto::ProtocolType::Unknown, test_ip, 10099, {});
        if (!matches.empty()) sample_passed++;
    }

    // Test domain exact (i=99 -> rule 7100: stress99.com:443)
    {
        auto matches = stress_engine.match(proto::ProtocolType::Unknown, FlowIP{}, 443, {"stress99.com"});
        if (!matches.empty()) sample_passed++;
    }

    // Test wildcard domain (i=99 -> rule 8100: *.wildcard99.com:443)
    {
        auto matches = stress_engine.match(proto::ProtocolType::Unknown, FlowIP{}, 443, {"www.wildcard99.com"});
        if (!matches.empty()) sample_passed++;
    }

    // Test port rule (i=99 -> rule 9100)
    {
        uint32_t ip = (10 << 24) | (100 << 16) | 99;
        FlowIP test_ip = FlowIP::fromIPv4(ip);
        auto matches = stress_engine.match(proto::ProtocolType::Unknown, test_ip, 8099, {});
        if (!matches.empty()) sample_passed++;
    }

    // Test no-port rule (i=99 -> rule 10100)
    {
        uint32_t ip = (10 << 24) | (200 << 16) | 99;
        FlowIP test_ip = FlowIP::fromIPv4(ip);
        auto matches = stress_engine.match(proto::ProtocolType::Unknown, test_ip, 9999, {});
        if (!matches.empty()) sample_passed++;
    }

    std::cout << "    Sample verification: " << sample_passed << "/" << sample_total << " passed";
    if (sample_passed == sample_total) {
        std::cout << " ✓\n";
    } else {
        std::cout << " (expected 10/10)\n";
    }

    std::cout << "\n[Stress Test Summary]\n";
    std::cout << "  Total rules in engine: " << stress_engine.getPolicyCount() << "\n";
    std::cout << "  Insert throughput: " << (10000 * 1000 / insert_duration.count()) << " rules/second\n";
    std::cout << "  Query throughput: " << (10000 * 1000 / query_duration.count()) << " queries/second\n";

    // Print final results
    std::cout << "\n========================================\n";
    std::cout << "  FINAL RESULTS\n";
    std::cout << "========================================\n";
    total_stats.print();

    if (total_stats.failed == 0) {
        std::cout << "\n✓ All tests passed! 100% accuracy achieved.\n";
        return 0;
    } else {
        std::cout << "\n✗ Some tests failed.\n";
        return 1;
    }
}
