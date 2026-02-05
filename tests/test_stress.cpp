#include "../src/Policy/policy_engine.hpp"
#include "../src/Protocol/protocol_detector.hpp"
#include <iostream>
#include <chrono>
#include <thread>
#include <vector>
#include <atomic>
#include <mach/mach.h>
#include <sys/resource.h>

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

// Get CPU usage
double getCPUUsage() {
    struct rusage usage;
    getrusage(RUSAGE_SELF, &usage);
    double user_time = usage.ru_utime.tv_sec + usage.ru_utime.tv_usec / 1000000.0;
    double sys_time = usage.ru_stime.tv_sec + usage.ru_stime.tv_usec / 1000000.0;
    return user_time + sys_time;
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

// High concurrency stress test
void stressTest(int rule_count, int queries_per_thread, int thread_count, int duration_seconds) {
    std::cout << "\n========================================\n";
    std::cout << "  High Concurrency Stress Test\n";
    std::cout << "========================================\n";
    std::cout << "Rules: " << rule_count << "\n";
    std::cout << "Threads: " << thread_count << "\n";
    std::cout << "Queries per thread: " << queries_per_thread << "\n";
    std::cout << "Duration: " << duration_seconds << " seconds\n\n";

    size_t mem_start = getCurrentMemoryUsage();
    double cpu_start = getCPUUsage();

    PolicyEngine* engine = new PolicyEngine();

    // Prepare policies in batch
    std::cout << "Preparing " << rule_count << " policies...\n";
    std::vector<Policy> policies;
    policies.reserve(rule_count);
    uint32_t rule_id = 1;

    for (int i = 0; i < rule_count; i++) {
        uint32_t ip = (10 << 24) | ((i / 256) << 16) | ((i % 256) << 8) | 1;
        std::string ip_str = std::to_string((ip >> 24) & 0xFF) + "." +
                           std::to_string((ip >> 16) & 0xFF) + "." +
                           std::to_string((ip >> 8) & 0xFF) + "." +
                           std::to_string(ip & 0xFF);
        policies.push_back(Policy{rule_id++, ip_str, "443"});
    }

    size_t mem_after_prepare = getCurrentMemoryUsage();
    std::cout << "Memory after preparing policies: " << formatBytes(mem_after_prepare)
              << " (+" << formatBytes(mem_after_prepare - mem_start) << ")\n";

    // Batch insert
    std::cout << "Inserting policies...\n";
    auto insert_start = std::chrono::high_resolution_clock::now();
    size_t added = engine->addPolicies(policies);
    auto insert_end = std::chrono::high_resolution_clock::now();
    auto insert_ms = std::chrono::duration_cast<std::chrono::milliseconds>(insert_end - insert_start);

    size_t mem_after_insert = getCurrentMemoryUsage();
    std::cout << "Inserted " << added << " rules in " << insert_ms.count() << "ms\n";
    std::cout << "Insert rate: " << (added * 1000 / insert_ms.count()) << " rules/sec\n";
    std::cout << "Memory after insert: " << formatBytes(mem_after_insert)
              << " (+" << formatBytes(mem_after_insert - mem_start) << ")\n\n";

    // Test IP
    FlowIP test_ip = FlowIP::fromIPv4((10 << 24) | (0 << 16) | (0 << 8) | 1);

    // Warmup
    for (int i = 0; i < 1000; i++) {
        engine->match(ProtocolType::Unknown, test_ip, 443, {});
    }

    std::cout << "Starting stress test with " << thread_count << " threads...\n";

    std::atomic<uint64_t> total_queries{0};
    std::atomic<uint64_t> total_matches{0};
    std::atomic<bool> stop_flag{false};
    std::vector<std::thread> threads;

    // Memory monitoring thread
    std::thread monitor_thread([&]() {
        size_t peak_memory = mem_after_insert;
        while (!stop_flag.load()) {
            std::this_thread::sleep_for(std::chrono::seconds(1));
            size_t current_mem = getCurrentMemoryUsage();
            if (current_mem > peak_memory) {
                peak_memory = current_mem;
            }
            uint64_t queries = total_queries.load();
            double elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::high_resolution_clock::now() - insert_end).count() / 1000.0;
            if (elapsed > 0) {
                std::cout << "  [" << (int)elapsed << "s] "
                          << "Queries: " << queries
                          << ", QPS: " << (uint64_t)(queries / elapsed)
                          << ", Memory: " << formatBytes(current_mem)
                          << ", Peak: " << formatBytes(peak_memory) << "\r" << std::flush;
            }
        }
        std::cout << "\nPeak memory during test: " << formatBytes(peak_memory)
                  << " (+" << formatBytes(peak_memory - mem_after_insert) << ")\n";
    });

    auto test_start = std::chrono::high_resolution_clock::now();

    // Launch worker threads
    for (int t = 0; t < thread_count; t++) {
        threads.emplace_back([&, t]() {
            uint64_t local_queries = 0;
            uint64_t local_matches = 0;

            for (int i = 0; i < queries_per_thread; i++) {
                auto matches = engine->match(ProtocolType::Unknown, test_ip, 443, {});
                local_matches += matches.size();
                local_queries++;

                if (local_queries % 1000 == 0) {
                    total_queries.fetch_add(1000);
                }
            }

            // Add remaining queries
            total_queries.fetch_add(local_queries % 1000);
            total_matches.fetch_add(local_matches);
        });
    }

    // Wait for all threads
    for (auto& thread : threads) {
        thread.join();
    }

    auto test_end = std::chrono::high_resolution_clock::now();
    stop_flag.store(true);
    monitor_thread.join();

    auto test_us = std::chrono::duration_cast<std::chrono::microseconds>(test_end - test_start);
    double cpu_end = getCPUUsage();
    size_t mem_end = getCurrentMemoryUsage();

    uint64_t final_queries = total_queries.load();
    uint64_t final_matches = total_matches.load();
    double test_seconds = test_us.count() / 1000000.0;
    double avg_latency_us = (double)test_us.count() / final_queries;
    double qps = final_queries / test_seconds;
    double cpu_time = cpu_end - cpu_start;
    double cpu_percent = (cpu_time / test_seconds) * 100.0;

    std::cout << "\n========================================\n";
    std::cout << "  Stress Test Results\n";
    std::cout << "========================================\n";
    std::cout << "Total queries: " << final_queries << "\n";
    std::cout << "Total time: " << test_seconds << " seconds\n";
    std::cout << "Average latency: " << avg_latency_us << " μs/query\n";
    std::cout << "Throughput: " << (uint64_t)qps << " QPS\n";
    std::cout << "Total matches: " << final_matches << "\n";
    std::cout << "\nResource Usage:\n";
    std::cout << "  CPU time: " << cpu_time << " seconds\n";
    std::cout << "  CPU utilization: " << cpu_percent << "%\n";
    std::cout << "  Memory start: " << formatBytes(mem_start) << "\n";
    std::cout << "  Memory end: " << formatBytes(mem_end) << "\n";
    std::cout << "  Memory delta: " << formatBytes(mem_end - mem_start) << "\n";

    delete engine;

    size_t mem_after_delete = getCurrentMemoryUsage();
    std::cout << "\nMemory after cleanup: " << formatBytes(mem_after_delete);
    if (mem_end > mem_after_delete) {
        std::cout << " (freed: " << formatBytes(mem_end - mem_after_delete) << ")\n";
    } else {
        std::cout << " (leaked: " << formatBytes(mem_after_delete - mem_end) << ")\n";
    }
}

int main() {
    std::cout << "========================================\n";
    std::cout << "  PolicyEngine Stress Test\n";
    std::cout << "  CPU & Memory Monitoring\n";
    std::cout << "========================================\n";

    // Test 1: 10K rules, 16 threads, 1M queries
    stressTest(10000, 62500, 16, 30);

    // Test 2: 50K rules, 16 threads, 1M queries
    std::cout << "\n\n";
    stressTest(50000, 62500, 16, 30);

    // Test 3: 100K rules, 16 threads, 1M queries
    std::cout << "\n\n";
    stressTest(100000, 62500, 16, 30);

    std::cout << "\n========================================\n";
    std::cout << "  All Stress Tests Complete\n";
    std::cout << "========================================\n";

    return 0;
}
