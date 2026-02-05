#include "../src/Policy/policy_engine.hpp"
#include "../src/Protocol/protocol_detector.hpp"
#include <iostream>
#include <chrono>
#include <vector>
#include <algorithm>
#include <iomanip>

using namespace policy;
using namespace flow;
using namespace proto;

// IPv4 CIDR only benchmark
void benchmarkIPv4CIDR(int rule_count) {
    std::cout << "\n=== IPv4 CIDR Benchmark (" << rule_count << " rules) ===\n";
    
    PolicyEngine engine;
    uint32_t rule_id = 1;
    
    auto start_insert = std::chrono::high_resolution_clock::now();
    
    for (int i = 0; i < rule_count; i++) {
        uint32_t network = (192 << 24) | ((i / 256) << 16) | ((i % 256) << 8);
        std::string cidr_str = std::to_string((network >> 24) & 0xFF) + "." +
                              std::to_string((network >> 16) & 0xFF) + "." +
                              std::to_string((network >> 8) & 0xFF) + ".0/24";
        Policy policy{rule_id++, cidr_str, "443"};
        engine.addPolicy(policy);
    }
    
    auto end_insert = std::chrono::high_resolution_clock::now();
    auto insert_duration = std::chrono::duration_cast<std::chrono::milliseconds>(end_insert - start_insert);
    
    std::cout << "Insert: " << insert_duration.count() << "ms ("
              << (rule_count * 1000 / insert_duration.count()) << " rules/sec)\n";
    
    // Test query
    FlowIP test_ip = FlowIP::fromIPv4((192 << 24) | (168 << 16) | (100 << 8) | 50);
    
    // Warmup
    for (int i = 0; i < 100; i++) {
        engine.match(ProtocolType::Unknown, test_ip, 443, {});
    }
    
    // Measure latencies
    std::vector<int64_t> latencies;
    latencies.reserve(1000);
    
    for (int i = 0; i < 1000; i++) {
        auto start = std::chrono::high_resolution_clock::now();
        auto matches = engine.match(ProtocolType::Unknown, test_ip, 443, {});
        auto end = std::chrono::high_resolution_clock::now();
        
        auto latency = std::chrono::duration_cast<std::chrono::nanoseconds>(end - start).count();
        latencies.push_back(latency);
    }
    
    std::sort(latencies.begin(), latencies.end());
    
    int64_t sum = 0;
    for (auto latency : latencies) sum += latency;
    
    std::cout << "Query Latency (1000 samples):\n";
    std::cout << "  Min:  " << latencies[0] / 1000.0 << " μs\n";
    std::cout << "  Avg:  " << (sum / 1000) / 1000.0 << " μs\n";
    std::cout << "  P50:  " << latencies[499] / 1000.0 << " μs\n";
    std::cout << "  P95:  " << latencies[949] / 1000.0 << " μs\n";
    std::cout << "  P99:  " << latencies[989] / 1000.0 << " μs\n";
    std::cout << "  Max:  " << latencies[999] / 1000.0 << " μs\n";
}

// Mixed rules benchmark
void benchmarkMixedRules(int rule_count) {
    std::cout << "\n=== Mixed Rules Benchmark (" << rule_count << " rules) ===\n";
    
    PolicyEngine engine;
    uint32_t rule_id = 1;
    
    auto start_insert = std::chrono::high_resolution_clock::now();
    
    int each_type = rule_count / 10;
    
    // IPv4 exact
    for (int i = 0; i < each_type; i++) {
        uint32_t ip = (10 << 24) | i;
        std::string ip_str = std::to_string((ip >> 24) & 0xFF) + "." +
                           std::to_string((ip >> 16) & 0xFF) + "." +
                           std::to_string((ip >> 8) & 0xFF) + "." +
                           std::to_string(ip & 0xFF);
        Policy policy{rule_id++, ip_str, "443"};
        engine.addPolicy(policy);
    }
    
    // IPv4 CIDR
    for (int i = 0; i < each_type; i++) {
        uint32_t network = (192 << 24) | (168 << 16) | i;
        std::string cidr_str = std::to_string((network >> 24) & 0xFF) + "." +
                              std::to_string((network >> 16) & 0xFF) + "." +
                              std::to_string((network >> 8) & 0xFF) + ".0/24";
        Policy policy{rule_id++, cidr_str, "443"};
        engine.addPolicy(policy);
    }
    
    // IPv4 Range
    for (int i = 0; i < each_type; i++) {
        std::string range_str = "172.16." + std::to_string(i) + ".1-172.16." + 
                              std::to_string(i) + ".100";
        Policy policy{rule_id++, range_str, "443"};
        engine.addPolicy(policy);
    }
    
    // IPv6 exact
    for (int i = 0; i < each_type; i++) {
        std::string ip_str = "2001:db8::" + std::to_string(i);
        Policy policy{rule_id++, ip_str, "443"};
        engine.addPolicy(policy);
    }
    
    // IPv6 CIDR
    for (int i = 0; i < each_type; i++) {
        std::string cidr_str = "2001:db8:" + std::to_string(i) + "::/64";
        Policy policy{rule_id++, cidr_str, "443"};
        engine.addPolicy(policy);
    }
    
    // IPv6 Range
    for (int i = 0; i < each_type; i++) {
        std::string range_str = "2001:db8:" + std::to_string(i) + "::1-2001:db8:" + 
                              std::to_string(i) + "::100";
        Policy policy{rule_id++, range_str, "443"};
        engine.addPolicy(policy);
    }
    
    // Domain exact
    for (int i = 0; i < each_type; i++) {
        Policy policy{rule_id++, "test" + std::to_string(i) + ".com", "443"};
        engine.addPolicy(policy);
    }
    
    // Wildcard domain
    for (int i = 0; i < each_type; i++) {
        Policy policy{rule_id++, "*.wild" + std::to_string(i) + ".com", "443"};
        engine.addPolicy(policy);
    }
    
    // Port rules
    for (int i = 0; i < each_type; i++) {
        Policy policy{rule_id++, "10.100.0.1", std::to_string(8000 + i)};
        engine.addPolicy(policy);
    }
    
    // No-port rules
    for (int i = 0; i < each_type; i++) {
        Policy policy{rule_id++, "10.200.0.1", ""};
        engine.addPolicy(policy);
    }
    
    auto end_insert = std::chrono::high_resolution_clock::now();
    auto insert_duration = std::chrono::duration_cast<std::chrono::milliseconds>(end_insert - start_insert);
    
    std::cout << "Insert: " << insert_duration.count() << "ms ("
              << (engine.getPolicyCount() * 1000 / insert_duration.count()) << " rules/sec)\n";
    std::cout << "Total rules: " << engine.getPolicyCount() << "\n";
    
    // Test query
    FlowIP test_ip = FlowIP::fromIPv4((192 << 24) | (168 << 16) | (100 << 8) | 50);
    
    // Warmup
    for (int i = 0; i < 100; i++) {
        engine.match(ProtocolType::Unknown, test_ip, 443, {});
    }
    
    // Measure latencies
    std::vector<int64_t> latencies;
    latencies.reserve(1000);
    
    for (int i = 0; i < 1000; i++) {
        auto start = std::chrono::high_resolution_clock::now();
        auto matches = engine.match(ProtocolType::Unknown, test_ip, 443, {});
        auto end = std::chrono::high_resolution_clock::now();
        
        auto latency = std::chrono::duration_cast<std::chrono::nanoseconds>(end - start).count();
        latencies.push_back(latency);
    }
    
    std::sort(latencies.begin(), latencies.end());
    
    int64_t sum = 0;
    for (auto latency : latencies) sum += latency;
    
    std::cout << "Query Latency (1000 samples):\n";
    std::cout << "  Min:  " << latencies[0] / 1000.0 << " μs\n";
    std::cout << "  Avg:  " << (sum / 1000) / 1000.0 << " μs\n";
    std::cout << "  P50:  " << latencies[499] / 1000.0 << " μs\n";
    std::cout << "  P95:  " << latencies[949] / 1000.0 << " μs\n";
    std::cout << "  P99:  " << latencies[989] / 1000.0 << " μs\n";
    std::cout << "  Max:  " << latencies[999] / 1000.0 << " μs\n";
}

int main() {
    std::cout << "========================================\n";
    std::cout << "  PolicyEngine Performance Benchmark\n";
    std::cout << "========================================\n";
    
    // Test different scales
    benchmarkIPv4CIDR(1000);
    benchmarkIPv4CIDR(10000);
    benchmarkMixedRules(1000);
    benchmarkMixedRules(10000);
    
    std::cout << "\n========================================\n";
    std::cout << "  Benchmark Complete\n";
    std::cout << "========================================\n";
    
    return 0;
}
