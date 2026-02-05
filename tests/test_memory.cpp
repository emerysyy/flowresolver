#include "../src/Policy/policy_engine.hpp"
#include <iostream>
#include <mach/mach.h>

using namespace policy;
using namespace flow;

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

int main() {
    std::cout << "========================================\n";
    std::cout << "  PolicyEngine Memory Analysis\n";
    std::cout << "========================================\n";

    size_t mem_start = getCurrentMemoryUsage();
    std::cout << "Initial memory: " << formatBytes(mem_start) << "\n\n";

    PolicyEngine* engine = new PolicyEngine();
    size_t mem_after_create = getCurrentMemoryUsage();
    std::cout << "After creating engine: " << formatBytes(mem_after_create)
              << " (+" << formatBytes(mem_after_create - mem_start) << ")\n\n";

    // Test different rule types separately
    std::cout << "Testing IPv4 exact match rules:\n";
    uint32_t rule_id = 1;

    // Prepare policies in batch
    std::vector<Policy> policies;
    policies.reserve(10000);

    for (int i = 0; i < 10000; i++) {
        uint32_t ip = (10 << 24) | ((i / 256) << 16) | ((i % 256) << 8) | 1;
        std::string ip_str = std::to_string((ip >> 24) & 0xFF) + "." +
                           std::to_string((ip >> 16) & 0xFF) + "." +
                           std::to_string((ip >> 8) & 0xFF) + "." +
                           std::to_string(ip & 0xFF);
        policies.push_back(Policy{rule_id++, ip_str, "443"});
    }

    std::cout << "Adding " << policies.size() << " policies in batch...\n";
    size_t mem_before_add = getCurrentMemoryUsage();

    size_t added = engine->addPolicies(policies);

    size_t mem_after_add = getCurrentMemoryUsage();
    std::cout << "Added " << added << " policies\n";
    std::cout << "Memory after batch add: " << formatBytes(mem_after_add)
              << " (+" << formatBytes(mem_after_add - mem_before_add) << ")\n";

    size_t mem_after_ipv4 = mem_after_add;
    std::cout << "\nTotal after 10000 IPv4 rules: " << formatBytes(mem_after_ipv4)
              << " (+" << formatBytes(mem_after_ipv4 - mem_after_create) << ")\n";
    std::cout << "Average per rule: " << ((mem_after_ipv4 - mem_after_create) / 10000) << " bytes\n";

    delete engine;
    size_t mem_after_delete = getCurrentMemoryUsage();

    std::cout << "\nAfter delete: " << formatBytes(mem_after_delete);
    if (mem_after_ipv4 > mem_after_delete) {
        std::cout << " (freed: " << formatBytes(mem_after_ipv4 - mem_after_delete) << ")\n";
    } else {
        std::cout << " (leaked: " << formatBytes(mem_after_delete - mem_after_ipv4) << ")\n";
    }

    std::cout << "\n========================================\n";
    std::cout << "  Memory Analysis Complete\n";
    std::cout << "========================================\n";

    return 0;
}
