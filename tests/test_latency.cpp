#include "../src/Policy/policy_engine.hpp"
#include "../src/Protocol/protocol_detector.hpp"
#include <iostream>
#include <chrono>
#include <vector>
#include <algorithm>

using namespace policy;
using namespace flow;
using namespace proto;

void printLatencyStats(const std::vector<int64_t>& latencies_ns, const std::string& title) {
    if (latencies_ns.empty()) return;
    
    int64_t sum = 0;
    int64_t min = latencies_ns[0];
    int64_t max = latencies_ns[0];
    
    for (auto latency : latencies_ns) {
        sum += latency;
        if (latency < min) min = latency;
        if (latency > max) max = latency;
    }
    
    std::cout << "\n" << title << ":\n";
    std::cout << "  Min: " << min / 1000.0 << " μs\n";
    std::cout << "  Avg: " << (sum / latencies_ns.size()) / 1000.0 << " μs\n";
    std::cout << "  P50: " << latencies_ns[latencies_ns.size() / 2] / 1000.0 << " μs\n";
    std::cout << "  P95: " << latencies_ns[static_cast<size_t>(latencies_ns.size() * 0.95)] / 1000.0 << " μs\n";
    std::cout << "  P99: " << latencies_ns[static_cast<size_t>(latencies_ns.size() * 0.99)] / 1000.0 << " μs\n";
    std::cout << "  Max: " << max / 1000.0 << " μs\n";
    std::cout << "  Throughput: " << (1000000000 / (sum / latencies_ns.size())) << " QPS\n";
}

int main() {
    std::cout << "========================================\n";
    std::cout << "  Single Query Latency Test\n";
    std::cout << "========================================\n";
    
    // Test with 10,000 mixed rules
    PolicyEngine engine;
    uint32_t rule_id = 1;
    
    std::cout << "\nInserting 10,000 mixed rules...\n";
    auto start = std::chrono::high_resolution_clock::now();
    
    // IPv4 exact: 1000
    for (int i = 0; i < 1000; i++) {
        uint32_t ip = (10 << 24) | i;
        std::string ip_str = std::to_string((ip >> 24) & 0xFF) + "." +
                           std::to_string((ip >> 16) & 0xFF) + "." +
                           std::to_string((ip >> 8) & 0xFF) + "." +
                           std::to_string(ip & 0xFF);
        Policy policy{rule_id++, ip_str, "443"};
        engine.addPolicy(policy);
    }
    
    // IPv4 CIDR: 1000
    for (int i = 0; i < 1000; i++) {
        uint32_t network = (192 << 24) | (168 << 16) | i;
        std::string cidr_str = std::to_string((network >> 24) & 0xFF) + "." +
                              std::to_string((network >> 16) & 0xFF) + "." +
                              std::to_string((network >> 8) & 0xFF) + ".0/24";
        Policy policy{rule_id++, cidr_str, "443"};
        engine.addPolicy(policy);
    }
    
    // IPv4 Range: 1000
    for (int i = 0; i < 1000; i++) {
        std::string range_str = "172.16." + std::to_string(i) + ".1-172.16." + 
                              std::to_string(i) + ".100";
        Policy policy{rule_id++, range_str, "443"};
        engine.addPolicy(policy);
    }
    
    // IPv6 exact: 1000
    for (int i = 0; i < 1000; i++) {
        std::string ip_str = "2001:db8::" + std::to_string(i);
        Policy policy{rule_id++, ip_str, "443"};
        engine.addPolicy(policy);
    }
    
    // IPv6 CIDR: 1000
    for (int i = 0; i < 1000; i++) {
        std::string cidr_str = "2001:db8:" + std::to_string(i) + "::/64";
        Policy policy{rule_id++, cidr_str, "443"};
        engine.addPolicy(policy);
    }
    
    // IPv6 Range: 1000
    for (int i = 0; i < 1000; i++) {
        std::string range_str = "2001:db8:" + std::to_string(i) + "::1-2001:db8:" + 
                              std::to_string(i) + "::100";
        Policy policy{rule_id++, range_str, "443"};
        engine.addPolicy(policy);
    }
    
    // Domain exact: 1000
    for (int i = 0; i < 1000; i++) {
        Policy policy{rule_id++, "test" + std::to_string(i) + ".com", "443"};
        engine.addPolicy(policy);
    }
    
    // Wildcard domain: 1000
    for (int i = 0; i < 1000; i++) {
        Policy policy{rule_id++, "*.wild" + std::to_string(i) + ".com", "443"};
        engine.addPolicy(policy);
    }
    
    // Port rules: 1000
    for (int i = 0; i < 1000; i++) {
        Policy policy{rule_id++, "10.100.0.1", std::to_string(8000 + i)};
        engine.addPolicy(policy);
    }
    
    // No-port rules: 1000
    for (int i = 0; i < 1000; i++) {
        Policy policy{rule_id++, "10.200.0.1", ""};
        engine.addPolicy(policy);
    }
    
    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
    
    std::cout << "Inserted " << engine.getPolicyCount() << " rules in " 
              << duration.count() << "ms\n";
    
    // Warmup
    FlowIP test_ip = FlowIP::fromIPv4((192 << 24) | (168 << 16) | (100 << 8) | 50);
    for (int i = 0; i < 100; i++) {
        engine.match(ProtocolType::Unknown, test_ip, 443, {});
    }
    
    // Test 1: IPv4 CIDR query (most common case)
    {
        std::vector<int64_t> latencies;
        latencies.reserve(10000);
        
        for (int i = 0; i < 10000; i++) {
            auto start = std::chrono::high_resolution_clock::now();
            auto matches = engine.match(ProtocolType::Unknown, test_ip, 443, {});
            auto end = std::chrono::high_resolution_clock::now();
            
            auto latency = std::chrono::duration_cast<std::chrono::nanoseconds>(end - start).count();
            latencies.push_back(latency);
        }
        
        std::sort(latencies.begin(), latencies.end());
        printLatencyStats(latencies, "IPv4 CIDR Query (10,000 samples)");
    }
    
    // Test 2: IPv4 exact match query
    {
        FlowIP exact_ip = FlowIP::fromIPv4((10 << 24) | 100);
        std::vector<int64_t> latencies;
        latencies.reserve(10000);
        
        for (int i = 0; i < 10000; i++) {
            auto start = std::chrono::high_resolution_clock::now();
            auto matches = engine.match(ProtocolType::Unknown, exact_ip, 443, {});
            auto end = std::chrono::high_resolution_clock::now();
            
            auto latency = std::chrono::duration_cast<std::chrono::nanoseconds>(end - start).count();
            latencies.push_back(latency);
        }
        
        std::sort(latencies.begin(), latencies.end());
        printLatencyStats(latencies, "IPv4 Exact Query (10,000 samples)");
    }
    
    // Test 3: Domain query
    {
        std::vector<int64_t> latencies;
        latencies.reserve(10000);
        
        for (int i = 0; i < 10000; i++) {
            auto start = std::chrono::high_resolution_clock::now();
            auto matches = engine.match(ProtocolType::Unknown, FlowIP{}, 443, 
                                      {"test100.com"});
            auto end = std::chrono::high_resolution_clock::now();
            
            auto latency = std::chrono::duration_cast<std::chrono::nanoseconds>(end - start).count();
            latencies.push_back(latency);
        }
        
        std::sort(latencies.begin(), latencies.end());
        printLatencyStats(latencies, "Domain Query (10,000 samples)");
    }
    
    // Test 4: Wildcard domain query
    {
        std::vector<int64_t> latencies;
        latencies.reserve(10000);
        
        for (int i = 0; i < 10000; i++) {
            auto start = std::chrono::high_resolution_clock::now();
            auto matches = engine.match(ProtocolType::Unknown, FlowIP{}, 443, 
                                      {"www.wild100.com"});
            auto end = std::chrono::high_resolution_clock::now();
            
            auto latency = std::chrono::duration_cast<std::chrono::nanoseconds>(end - start).count();
            latencies.push_back(latency);
        }
        
        std::sort(latencies.begin(), latencies.end());
        printLatencyStats(latencies, "Wildcard Domain Query (10,000 samples)");
    }
    
    // Test 5: Port rule query
    {
        FlowIP port_ip = FlowIP::fromIPv4((10 << 24) | (100 << 16) | 1);
        std::vector<int64_t> latencies;
        latencies.reserve(10000);
        
        for (int i = 0; i < 10000; i++) {
            auto start = std::chrono::high_resolution_clock::now();
            auto matches = engine.match(ProtocolType::Unknown, port_ip, 8100, {});
            auto end = std::chrono::high_resolution_clock::now();
            
            auto latency = std::chrono::duration_cast<std::chrono::nanoseconds>(end - start).count();
            latencies.push_back(latency);
        }
        
        std::sort(latencies.begin(), latencies.end());
        printLatencyStats(latencies, "Port Rule Query (10,000 samples)");
    }
    
    // Test 6: No-port rule query
    {
        FlowIP noport_ip = FlowIP::fromIPv4((10 << 24) | (200 << 16) | 1);
        std::vector<int64_t> latencies;
        latencies.reserve(10000);
        
        for (int i = 0; i < 10000; i++) {
            auto start = std::chrono::high_resolution_clock::now();
            auto matches = engine.match(ProtocolType::Unknown, noport_ip, 9999, {});
            auto end = std::chrono::high_resolution_clock::now();
            
            auto latency = std::chrono::duration_cast<std::chrono::nanoseconds>(end - start).count();
            latencies.push_back(latency);
        }
        
        std::sort(latencies.begin(), latencies.end());
        printLatencyStats(latencies, "No-Port Rule Query (10,000 samples)");
    }
    
    std::cout << "\n========================================\n";
    std::cout << "  Test Complete\n";
    std::cout << "========================================\n";
    
    return 0;
}
