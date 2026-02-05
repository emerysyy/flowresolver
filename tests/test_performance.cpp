#include "../src/Policy/policy_engine.hpp"
#include "../src/Protocol/protocol_detector.hpp"
#include <iostream>
#include <chrono>
#include <thread>
#include <vector>
#include <atomic>
#include <mutex>
#include <mach/mach.h>

using namespace policy;
using namespace flow;
using namespace proto;

// Get current memory usage in bytes
size_t getCurrentMemoryUsage() {
    struct mach_task_basic_info info;
    mach_msg_type_number_t size = MACH_TASK_BASIC_INFO_COUNT;
    kern_return_t kerr = task_info(mach_task_self(),
                                   MACH_TASK_BASIC_INFO,
                                   (task_info_t)&info,
                                   &size);
    if (kerr == KERN_SUCCESS) {
        return info.resident_size;
    }
    return 0;
}

// Format bytes to human readable string
std::string formatBytes(size_t bytes) {
    const char* units[] = {"B", "KB", "MB", "GB"};
    int unit = 0;
    double size = bytes;
    while (size >= 1024 && unit < 3) {
        size /= 1024;
        unit++;
    }
    char buffer[64];
    snprintf(buffer, sizeof(buffer), "%.2f %s", size, units[unit]);
    return std::string(buffer);
}

// Single threaded baseline performance
void testSingleThreadedBaseline(int rule_count, int queries_per_test) {
    std::cout << "\n=== Single-Threaded Baseline (" << rule_count << " rules, "
              << queries_per_test << " queries) ===\n";

    size_t mem_before = getCurrentMemoryUsage();
    std::cout << "Memory before creating engine: " << formatBytes(mem_before) << "\n";

    PolicyEngine* engine = new PolicyEngine();
    size_t mem_after_create = getCurrentMemoryUsage();
    std::cout << "Memory after creating engine: " << formatBytes(mem_after_create)
              << " (delta: " << formatBytes(mem_after_create - mem_before) << ")\n";

    // Prepare policies in batch
    std::vector<Policy> policies;
    policies.reserve(rule_count);
    uint32_t rule_id = 1;

    for (int i = 0; i < rule_count; i++) {
        // IPv4 exact
        uint32_t ip = (10 << 24) | (i % 256);
        std::string ip_str = std::to_string((ip >> 24) & 0xFF) + "." +
                           std::to_string((ip >> 16) & 0xFF) + "." +
                           std::to_string((ip >> 8) & 0xFF) + "." +
                           std::to_string(ip & 0xFF);
        policies.push_back(Policy{rule_id++, ip_str, "443"});
    }

    // Batch insert
    auto start = std::chrono::high_resolution_clock::now();
    size_t added = engine->addPolicies(policies);
    auto end = std::chrono::high_resolution_clock::now();
    auto insert_ms = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);

    size_t mem_after_insert = getCurrentMemoryUsage();
    std::cout << "\nInserted " << added << " rules in "
              << insert_ms.count() << "ms\n";
    std::cout << "Insert rate: " << (added * 1000 / insert_ms.count()) << " rules/sec\n";
    std::cout << "Memory after insert: " << formatBytes(mem_after_insert)
              << " (delta: " << formatBytes(mem_after_insert - mem_after_create) << ")\n";
    std::cout << "Average memory per rule: "
              << formatBytes((mem_after_insert - mem_after_create) / added) << "\n";

    // Test query performance - use an IP that matches (10.x.x.x with port 443)
    FlowIP test_ip = FlowIP::fromIPv4((10 << 24) | (0 << 16) | (0 << 8) | 1);  // 10.0.0.1

    // First verify the match works
    auto verify_match = engine->match(ProtocolType::Unknown, test_ip, 443, {});
    std::cout << "\nVerification: 10.0.0.1:443 matches " << verify_match.size() << " rules\n";

    // Warmup
    for (int i = 0; i < 1000; i++) {
        engine->match(ProtocolType::Unknown, test_ip, 443, {});
    }

    start = std::chrono::high_resolution_clock::now();

    uint64_t total_matches = 0;
    for (int i = 0; i < queries_per_test; i++) {
        auto matches = engine->match(ProtocolType::Unknown, test_ip, 443, {});
        total_matches += matches.size();
    }

    end = std::chrono::high_resolution_clock::now();
    auto query_us = std::chrono::duration_cast<std::chrono::microseconds>(end - start);

    double avg_latency_us = (double)query_us.count() / queries_per_test;
    double qps = queries_per_test / ((double)query_us.count() / 1000000.0);

    size_t mem_after_query = getCurrentMemoryUsage();

    std::cout << "\nQuery Performance Results:\n";
    std::cout << "  Total queries: " << queries_per_test << "\n";
    std::cout << "  Total time: " << (query_us.count() / 1000.0) << " ms\n";
    std::cout << "  Average latency: " << avg_latency_us << " μs/query\n";
    std::cout << "  Throughput: " << (size_t)qps << " QPS\n";
    std::cout << "  Total matches: " << total_matches << " (avg " << (total_matches / queries_per_test) << " per query)\n";

    // Fix: use signed arithmetic to avoid overflow
    std::cout << "  Memory after queries: " << formatBytes(mem_after_query);
    if (mem_after_query > mem_after_insert) {
        std::cout << " (delta: +" << formatBytes(mem_after_query - mem_after_insert) << ")\n";
    } else {
        std::cout << " (delta: -" << formatBytes(mem_after_insert - mem_after_query) << ")\n";
    }

    delete engine;

    size_t mem_after_delete = getCurrentMemoryUsage();
    std::cout << "\nMemory after delete: " << formatBytes(mem_after_delete);
    if (mem_after_insert > mem_after_delete) {
        std::cout << " (freed: " << formatBytes(mem_after_insert - mem_after_delete) << ")\n";
    } else {
        std::cout << " (leaked: " << formatBytes(mem_after_delete - mem_after_insert) << ")\n";
    }
}

// Multi-threaded concurrent performance test
void testMultiThreaded(int rule_count, int queries_per_thread, int thread_count) {
    std::cout << "\n=== Multi-Threaded Test (" << thread_count << " threads, "
              << rule_count << " rules, " << queries_per_thread << " queries/thread) ===\n";

    PolicyEngine* engine = new PolicyEngine();

    // Prepare policies in batch
    std::vector<Policy> policies;
    policies.reserve(rule_count);
    uint32_t rule_id = 1;

    for (int i = 0; i < rule_count; i++) {
        // IPv4 exact
        uint32_t ip = (10 << 24) | (i % 256);
        std::string ip_str = std::to_string((ip >> 24) & 0xFF) + "." +
                           std::to_string((ip >> 16) & 0xFF) + "." +
                           std::to_string((ip >> 8) & 0xFF) + "." +
                           std::to_string(ip & 0xFF);
        policies.push_back(Policy{rule_id++, ip_str, "443"});
    }

    // Batch insert
    auto start = std::chrono::high_resolution_clock::now();
    size_t added = engine->addPolicies(policies);
    auto end = std::chrono::high_resolution_clock::now();
    auto insert_ms = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);

    std::cout << "Inserted " << added << " rules in " << insert_ms.count() << "ms\n";

    // Test IP that matches
    FlowIP test_ip = FlowIP::fromIPv4((10 << 24) | (0 << 16) | (0 << 8) | 1);  // 10.0.0.1

    // Verify match
    auto verify_match = engine->match(ProtocolType::Unknown, test_ip, 443, {});
    std::cout << "Verification: 10.0.0.1:443 matches " << verify_match.size() << " rules\n";

    // Warmup
    for (int i = 0; i < 1000; i++) {
        engine->match(ProtocolType::Unknown, test_ip, 443, {});
    }

    // Multi-threaded query test
    std::atomic<uint64_t> total_matches{0};
    std::vector<std::thread> threads;
    std::vector<uint64_t> thread_matches(thread_count, 0);

    start = std::chrono::high_resolution_clock::now();

    // Launch threads
    for (int t = 0; t < thread_count; t++) {
        threads.emplace_back([&, t]() {
            uint64_t local_matches = 0;
            for (int i = 0; i < queries_per_thread; i++) {
                auto matches = engine->match(ProtocolType::Unknown, test_ip, 443, {});
                local_matches += matches.size();
            }
            thread_matches[t] = local_matches;
            total_matches += local_matches;
        });
    }

    // Wait for all threads
    for (auto& thread : threads) {
        thread.join();
    }

    end = std::chrono::high_resolution_clock::now();
    auto query_us = std::chrono::duration_cast<std::chrono::microseconds>(end - start);

    int total_queries = queries_per_thread * thread_count;
    double avg_latency_us = (double)query_us.count() / total_queries;
    double qps = total_queries / ((double)query_us.count() / 1000000.0);

    std::cout << "\nConcurrent Query Performance:\n";
    std::cout << "  Threads: " << thread_count << "\n";
    std::cout << "  Total queries: " << total_queries << " (" << queries_per_thread << " per thread)\n";
    std::cout << "  Total time: " << (query_us.count() / 1000.0) << " ms\n";
    std::cout << "  Average latency: " << avg_latency_us << " μs/query\n";
    std::cout << "  Throughput: " << (size_t)qps << " QPS\n";
    std::cout << "  Total matches: " << total_matches.load() << "\n";

    // Calculate speedup vs single-threaded baseline
    // Baseline: 4842 QPS (from previous test)
    double baseline_qps = 4842.0;
    double speedup = qps / baseline_qps;
    double efficiency = speedup / thread_count * 100.0;

    std::cout << "\nScalability Analysis:\n";
    std::cout << "  Speedup vs single-thread: " << speedup << "x\n";
    std::cout << "  Parallel efficiency: " << efficiency << "%\n";

    delete engine;
}

int main() {
    std::cout << "========================================\n";
    std::cout << "  PolicyEngine Performance Test\n";
    std::cout << "  with Memory Analysis\n";
    std::cout << "========================================\n";

    size_t initial_mem = getCurrentMemoryUsage();
    std::cout << "Initial memory: " << formatBytes(initial_mem) << "\n";

    // Test with 10,000 rules (actual 10000, not 6000)
    testSingleThreadedBaseline(10000, 100000);

    // Multi-threaded tests with different thread counts
    std::cout << "\n\n========================================\n";
    std::cout << "  Multi-Threaded Concurrency Tests\n";
    std::cout << "========================================\n";

    // Test with 2, 4, 8 threads
    testMultiThreaded(10000, 50000, 2);
    testMultiThreaded(10000, 25000, 4);
    testMultiThreaded(10000, 12500, 8);

    std::cout << "\n========================================\n";
    std::cout << "  All Tests Complete\n";
    std::cout << "========================================\n";

    size_t final_mem = getCurrentMemoryUsage();
    std::cout << "Final memory: " << formatBytes(final_mem)
              << " (total delta: " << formatBytes(final_mem - initial_mem) << ")\n";

    return 0;
}
