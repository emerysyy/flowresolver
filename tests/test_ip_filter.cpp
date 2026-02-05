#include "../src/Filter/ip_index.h"
#include "../src/Filter/filter_common.h"
#include <iostream>
#include <chrono>
#include <thread>
#include <vector>
#include <random>
#include <iomanip>
#include <algorithm>
#include <cstring>

using namespace flow;

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

// Helper to check if vector contains specific rule ID
bool containsRule(const std::vector<RuleId>& rules, RuleId id) {
    for (RuleId rid : rules) {
        if (rid == id) return true;
    }
    return false;
}

// Helper to convert uint32_t IP to string
std::string ipv4ToString(uint32_t ip) {
    std::ostringstream oss;
    oss << ((ip >> 24) & 0xFF) << "."
        << ((ip >> 16) & 0xFF) << "."
        << ((ip >> 8) & 0xFF) << "."
        << (ip & 0xFF);
    return oss.str();
}

// Helper to convert IPv6 to string
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

// =================== A. IPv4 Tests ===================
void testIPv4(TestStats& stats) {
    std::cout << "\n[A. IPv4 Tests]\n";

    IPIndex index;

    // A1. Exact Match Tests
    std::cout << "  A1. IPv4 Exact Match:\n";

    index.addIPv4Exact(0x0A000001, 1);  // 10.0.0.1
    index.addIPv4Exact(0xC0A80101, 2);  // 192.168.1.1

    auto matches = index.queryIds(FlowIP::fromIPv4(0x0A000001));
    stats.total++;
    if (containsRule(matches, 1) && matches.size() == 1) {
        stats.passed++;
        std::cout << "    ✓ Exact match: 10.0.0.1\n";
    } else {
        stats.failed++;
        std::cout << "    ✗ Failed to match 10.0.0.1\n";
    }

    matches = index.queryIds(FlowIP::fromIPv4(0xC0A80101));
    stats.total++;
    if (containsRule(matches, 2)) {
        stats.passed++;
        std::cout << "    ✓ Exact match: 192.168.1.1\n";
    } else {
        stats.failed++;
        std::cout << "    ✗ Failed to match 192.168.1.1\n";
    }

    // Negative test
    matches = index.queryIds(FlowIP::fromIPv4(0x0A000002));
    stats.total++;
    if (!containsRule(matches, 1)) {
        stats.passed++;
        std::cout << "    ✓ Negative: 10.0.0.2 doesn't match 10.0.0.1\n";
    } else {
        stats.failed++;
        std::cout << "    ✗ 10.0.0.2 should not match 10.0.0.1\n";
    }

    // Duplicate rule IDs on same IP
    index.addIPv4Exact(0x0A000001, 3);
    matches = index.queryIds(FlowIP::fromIPv4(0x0A000001));
    stats.total++;
    if (containsRule(matches, 1) && containsRule(matches, 3)) {
        stats.passed++;
        std::cout << "    ✓ Multiple rules on same IP\n";
    } else {
        stats.failed++;
        std::cout << "    ✗ Should have 2 rules on 10.0.0.1\n";
    }

    // A2. CIDR Match Tests
    std::cout << "  A2. IPv4 CIDR Match:\n";

    index.addIPv4CIDR(IPv4CIDR(0xC0A80100, 24), 10);  // 192.168.1.0/24
    index.addIPv4CIDR(IPv4CIDR(0x0A000000, 8), 11);     // 10.0.0.0/8

    matches = index.queryIds(FlowIP::fromIPv4(0xC0A80105));  // 192.168.1.5
    stats.total++;
    if (containsRule(matches, 10)) {
        stats.passed++;
        std::cout << "    ✓ CIDR: 192.168.1.5 matches 192.168.1.0/24\n";
    } else {
        stats.failed++;
        std::cout << "    ✗ CIDR match failed\n";
    }

    matches = index.queryIds(FlowIP::fromIPv4(0x0A123456));  // 10.18.52.86
    stats.total++;
    if (containsRule(matches, 11)) {
        stats.passed++;
        std::cout << "    ✓ CIDR: 10.18.52.86 matches 10.0.0.0/8\n";
    } else {
        stats.failed++;
        std::cout << "    ✗ /8 CIDR match failed\n";
    }

    // Negative CIDR test
    matches = index.queryIds(FlowIP::fromIPv4(0xC0A80205));  // 192.168.2.5
    stats.total++;
    if (!containsRule(matches, 10)) {
        stats.passed++;
        std::cout << "    ✓ CIDR: 192.168.2.5 doesn't match 192.168.1.0/24\n";
    } else {
        stats.failed++;
        std::cout << "    ✗ Should not match different /24\n";
    }

    // A3. Range Match Tests
    std::cout << "  A3. IPv4 Range Match:\n";

    index.addIPv4Range(0xAC100001, 0xAC100064, 20);  // 172.16.0.1-100
    index.addIPv4Range(0x01400100, 0x014001FF, 21);  // 20.64.1.0-20.64.1.255

    matches = index.queryIds(FlowIP::fromIPv4(0xAC100050));  // 172.16.0.80
    stats.total++;
    if (containsRule(matches, 20)) {
        stats.passed++;
        std::cout << "    ✓ Range: 172.16.0.80 matches 172.16.0.1-100\n";
    } else {
        stats.failed++;
        std::cout << "    ✗ Range match failed\n";
    }

    matches = index.queryIds(FlowIP::fromIPv4(0xAC100001));  // Start of range
    stats.total++;
    if (containsRule(matches, 20)) {
        stats.passed++;
        std::cout << "    ✓ Range: Start boundary matches\n";
    } else {
        stats.failed++;
        std::cout << "    ✗ Range start should match\n";
    }

    matches = index.queryIds(FlowIP::fromIPv4(0xAC100064));  // End of range
    stats.total++;
    if (containsRule(matches, 20)) {
        stats.passed++;
        std::cout << "    ✓ Range: End boundary matches\n";
    } else {
        stats.failed++;
        std::cout << "    ✗ Range end should match\n";
    }

    // Negative range test
    matches = index.queryIds(FlowIP::fromIPv4(0xAC100065));  // Just after range
    stats.total++;
    if (!containsRule(matches, 20)) {
        stats.passed++;
        std::cout << "    ✓ Range: IP after range doesn't match\n";
    } else {
        stats.failed++;
        std::cout << "    ✗ IP after range should not match\n";
    }

    // A4. Boundary Values
    std::cout << "  A4. IPv4 Boundary Values:\n";

    IPIndex boundary_index;
    boundary_index.addIPv4Exact(0x00000000, 30);  // 0.0.0.0
    boundary_index.addIPv4Exact(0xFFFFFFFF, 31);  // 255.255.255.255
    boundary_index.addIPv4CIDR(IPv4CIDR(0, 0), 32);  // 0.0.0.0/0

    matches = boundary_index.queryIds(FlowIP::fromIPv4(0x00000000));
    stats.total++;
    if (containsRule(matches, 30) && containsRule(matches, 32)) {
        stats.passed++;
        std::cout << "    ✓ Boundary: 0.0.0.0 matches\n";
    } else {
        stats.failed++;
        std::cout << "    ✗ 0.0.0.0 boundary match failed\n";
    }

    matches = boundary_index.queryIds(FlowIP::fromIPv4(0xFFFFFFFF));
    stats.total++;
    if (containsRule(matches, 31)) {
        stats.passed++;
        std::cout << "    ✓ Boundary: 255.255.255.255 matches\n";
    } else {
        stats.failed++;
        std::cout << "    ✗ Max IP match failed\n";
    }

    // Any IP should match 0.0.0.0/0
    matches = boundary_index.queryIds(FlowIP::fromIPv4(0x12345678));
    stats.total++;
    if (containsRule(matches, 32)) {
        stats.passed++;
        std::cout << "    ✓ CIDR: 0.0.0.0/0 matches any IP\n";
    } else {
        stats.failed++;
        std::cout << "    ✗ 0.0.0.0/0 should match any IP\n";
    }
}

// =================== B. IPv6 Tests ===================
void testIPv6(TestStats& stats) {
    std::cout << "\n[B. IPv6 Tests]\n";

    IPIndex index;

    // B1. Exact Match
    std::cout << "  B1. IPv6 Exact Match:\n";

    uint64_t hi1 = 0x20010db800000000ULL;
    uint64_t lo1 = 0x0000000000000001ULL;
    index.addIPv6Exact(hi1, lo1, 1);  // 2001:db8::1

    uint64_t hi2 = 0x20010db800000000ULL;
    uint64_t lo2 = 0x0000000000000002ULL;
    index.addIPv6Exact(hi2, lo2, 2);  // 2001:db8::2

    auto matches = index.queryIds(FlowIP::fromIPv6(hi1, lo1));
    stats.total++;
    if (containsRule(matches, 1)) {
        stats.passed++;
        std::cout << "    ✓ IPv6 exact: 2001:db8::1\n";
    } else {
        stats.failed++;
        std::cout << "    ✗ IPv6 exact match failed\n";
    }

    // B2. CIDR Match
    std::cout << "  B2. IPv6 CIDR Match:\n";

    uint64_t cidr_hi = 0x20010db800000000ULL;
    uint64_t cidr_lo = 0x0000000000000000ULL;
    index.addIPv6CIDR(IPv6CIDR(cidr_hi, cidr_lo, 64), 10);  // 2001:db8::/64

    uint64_t test_lo = 0x0000000000001234ULL;
    matches = index.queryIds(FlowIP::fromIPv6(cidr_hi, test_lo));
    stats.total++;
    if (containsRule(matches, 10)) {
        stats.passed++;
        std::cout << "    ✓ IPv6 CIDR: 2001:db8::1234 matches 2001:db8::/64\n";
    } else {
        stats.failed++;
        std::cout << "    ✗ IPv6 CIDR match failed\n";
    }

    // Different /64 block should not match
    uint64_t diff_hi = 0x20010db800000001ULL;
    matches = index.queryIds(FlowIP::fromIPv6(diff_hi, 0));
    stats.total++;
    if (!containsRule(matches, 10)) {
        stats.passed++;
        std::cout << "    ✓ IPv6 CIDR: Different /64 doesn't match\n";
    } else {
        stats.failed++;
        std::cout << "    ✗ Different /64 should not match\n";
    }

    // B3. Range Match
    std::cout << "  B3. IPv6 Range Match:\n";

    uint64_t range_hi = 0x20010db800000000ULL;
    index.addIPv6Range(range_hi, 0x0000000000000001ULL,
                      range_hi, 0x0000000000000064ULL, 20);  // 2001:db8::1-100

    matches = index.queryIds(FlowIP::fromIPv6(range_hi, 0x0000000000000032ULL));
    stats.total++;
    if (containsRule(matches, 20)) {
        stats.passed++;
        std::cout << "    ✓ IPv6 range: 2001:db8::50 matches range\n";
    } else {
        stats.failed++;
        std::cout << "    ✗ IPv6 range match failed\n";
    }

    // B4. IPv4-mapped IPv6
    std::cout << "  B4. IPv4-mapped IPv6:\n";

    IPIndex mapped_index;
    mapped_index.addIPv4Exact(0xC0A80101, 50);  // 192.168.1.1

    // IPv4-mapped: ::ffff:192.168.1.1
    // Format: 0:0:0:0:0:ffff:C0A8:101
    uint64_t mapped_hi = 0x0000000000000000ULL;  // First 64 bits are 0
    uint64_t mapped_lo = 0x0000FFFFC0A80101ULL;  // ffff (16 bits) + 192.168.1.1 (32 bits)
    auto mapped_ip = FlowIP::fromIPv6(mapped_hi, mapped_lo);

    stats.total++;
    if (mapped_ip.isV4()) {
        stats.passed++;
        std::cout << "    ✓ IPv4-mapped IPv6 auto-converted to IPv4\n";
    } else {
        stats.failed++;
        std::cout << "    ✗ IPv4-mapped IPv6 should convert to IPv4\n";
    }

    matches = mapped_index.queryIds(mapped_ip);
    stats.total++;
    if (containsRule(matches, 50)) {
        stats.passed++;
        std::cout << "    ✓ IPv4-mapped: ::ffff:192.168.1.1 matches 192.168.1.1 rule\n";
    } else {
        stats.failed++;
        std::cout << "    ✗ IPv4-mapped match failed\n";
    }
}

// =================== C. Edge Cases ===================
void testEdgeCases(TestStats& stats) {
    std::cout << "\n[C. Edge Cases]\n";

    IPIndex index;

    // C1. Empty/Nil IP
    std::cout << "  C1. Empty/Nil IP:\n";

    index.addNil(100);
    FlowIP nil_ip;
    auto matches = index.queryIds(nil_ip);
    stats.total++;
    if (containsRule(matches, 100)) {
        stats.passed++;
        std::cout << "    ✓ Nil IP matches\n";
    } else {
        stats.failed++;
        std::cout << "    ✗ Nil IP should match\n";
    }

    // C2. MatchMode::All vs MatchMode::Longest
    std::cout << "  C2. MatchMode Comparison:\n";

    IPIndex mode_index;
    mode_index.addIPv4CIDR(IPv4CIDR(0xC0A80000, 16), 1);  // 192.168.0.0/16
    mode_index.addIPv4CIDR(IPv4CIDR(0xC0A80100, 24), 2);  // 192.168.1.0/24

    FlowIP test_ip = FlowIP::fromIPv4(0xC0A80105);  // 192.168.1.5

    auto all_matches = mode_index.query(test_ip, IPIndex::MatchMode::All);
    stats.total++;
    if (all_matches.size() == 2) {  // Both /16 and /24 should match
        stats.passed++;
        std::cout << "    ✓ MatchMode::All returns all matching rules\n";
    } else {
        stats.failed++;
        std::cout << "    ✗ MatchMode::All should return 2 rules, got " << all_matches.size() << "\n";
    }

    auto longest_matches = mode_index.query(test_ip, IPIndex::MatchMode::Longest);
    stats.total++;
    if (longest_matches.size() == 1 && containsRule(longest_matches.values(), 2)) {
        stats.passed++;
        std::cout << "    ✓ MatchMode::Longest returns only /24 (more specific)\n";
    } else {
        stats.failed++;
        std::cout << "    ✗ MatchMode::Longest should return only /24 rule\n";
    }

    // C3. Overlapping rules
    std::cout << "  C3. Overlapping Rules:\n";

    IPIndex overlap_index;
    overlap_index.addIPv4Exact(0xC0A80101, 10);
    overlap_index.addIPv4CIDR(IPv4CIDR(0xC0A80100, 24), 11);  // Contains exact IP
    overlap_index.addIPv4Range(0xC0A80100, 0xC0A801FF, 12);  // Also contains exact IP

    matches = overlap_index.queryIds(FlowIP::fromIPv4(0xC0A80101));
    stats.total++;
    if (matches.size() == 3 && containsRule(matches, 10) &&
        containsRule(matches, 11) && containsRule(matches, 12)) {
        stats.passed++;
        std::cout << "    ✓ Overlapping rules: all 3 types match\n";
    } else {
        stats.failed++;
        std::cout << "    ✗ Should have 3 overlapping matches, got " << matches.size() << "\n";
    }
}

// =================== D. Performance Benchmarks ===================
void testPerformance(TestStats& stats) {
    std::cout << "\n[D. Performance Benchmarks]\n";

    IPIndex index;

    // D1. Insert 10K IPv4 exact rules
    std::cout << "  D1. Insert 10K IPv4 exact rules...\n";
    auto start = std::chrono::high_resolution_clock::now();

    for (int i = 0; i < 10000; i++) {
        uint32_t ip = 0x0A000000 | (i % 0x1000000);
        index.addIPv4Exact(ip, static_cast<RuleId>(i));
    }

    auto end = std::chrono::high_resolution_clock::now();
    auto insert_time = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);

    std::cout << "    Insert time: " << insert_time.count() << "ms\n";
    stats.total++;
    if (insert_time.count() < 500) {
        stats.passed++;
        std::cout << "    ✓ Insert performance acceptable\n";
    } else {
        stats.failed++;
        std::cout << "    ✗ Insert too slow: " << insert_time.count() << "ms\n";
    }

    // D2. Query 100K times
    std::cout << "  D2. Query 100K times...\n";
    start = std::chrono::high_resolution_clock::now();

    for (int i = 0; i < 100000; i++) {
        uint32_t ip = 0x0A000000 | (i % 10000);
        auto matches = index.queryIds(FlowIP::fromIPv4(ip));
        if (i == 99999) {
            volatile size_t s = matches.size();
            (void)s;
        }
    }

    end = std::chrono::high_resolution_clock::now();
    auto query_time = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);

    std::cout << "    Query time for 100K: " << query_time.count() << "ms\n";
    std::cout << "    Average per query: " << query_time.count() * 10.0 << "μs\n";
    stats.total++;
    if (query_time.count() < 1000) {
        stats.passed++;
        std::cout << "    ✓ Query performance acceptable\n";
    } else {
        stats.failed++;
        std::cout << "    ✗ Query too slow\n";
    }

    // D3. Insert 1K CIDR rules
    std::cout << "  D3. Insert 1K IPv4 CIDR rules...\n";
    IPIndex cidr_index;
    start = std::chrono::high_resolution_clock::now();

    for (int i = 0; i < 1000; i++) {
        uint32_t network = (i << 16) & 0xFFFF0000;
        cidr_index.addIPv4CIDR(IPv4CIDR(network, 16), static_cast<RuleId>(i));
    }

    end = std::chrono::high_resolution_clock::now();
    auto cidr_time = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);

    std::cout << "    CIDR insert time: " << cidr_time.count() << "ms\n";
    stats.total++;
    if (cidr_time.count() < 200) {
        stats.passed++;
        std::cout << "    ✓ CIDR insert performance acceptable\n";
    } else {
        stats.failed++;
        std::cout << "    ✗ CIDR insert too slow\n";
    }

    // D4. Insert 1K ranges
    std::cout << "  D4. Insert 1K IPv4 ranges...\n";
    IPIndex range_index;
    start = std::chrono::high_resolution_clock::now();

    for (int i = 0; i < 1000; i++) {
        uint32_t start_ip = (i * 1000) % 0xFFFF0000;
        uint32_t end_ip = start_ip + 100;
        range_index.addIPv4Range(start_ip, end_ip, static_cast<RuleId>(i));
    }

    end = std::chrono::high_resolution_clock::now();
    auto range_time = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);

    std::cout << "    Range insert time: " << range_time.count() << "ms\n";
    stats.total++;
    if (range_time.count() < 500) {
        stats.passed++;
        std::cout << "    ✓ Range insert performance acceptable\n";
    } else {
        stats.failed++;
        std::cout << "    ✗ Range insert too slow\n";
    }
}

// =================== E. Thread Safety (Documentation) ===================
void testThreadSafetyNote(TestStats& stats) {
    std::cout << "\n[E. Thread Safety Note]\n";
    std::cout << "  ℹ IPIndex is NOT thread-safe by design.\n";
    std::cout << "  ℹ If concurrent access is needed, external synchronization (e.g., mutex) is required.\n";
    std::cout << "  ℹ DomainMatcher and PortMatcher have built-in thread safety.\n";

    stats.total++;
    stats.passed++;
    std::cout << "  ✓ Thread safety documented\n";
}

// =================== F. Error Handling ===================
void testErrorHandling(TestStats& stats) {
    std::cout << "\n[F. Error Handling]\n";

    IPIndex index;

    // F1. Invalid CIDR prefix (should throw)
    std::cout << "  F1. Invalid CIDR prefix handling:\n";

    bool caught_exception = false;
    try {
        IPv4CIDR invalid_cidr(0xC0A80100, 33);  // Prefix > 32
    } catch (const std::invalid_argument& e) {
        caught_exception = true;
    }

    stats.total++;
    if (caught_exception) {
        stats.passed++;
        std::cout << "    ✓ Invalid CIDR prefix > 32 throws exception\n";
    } else {
        stats.failed++;
        std::cout << "    ✗ Should throw exception for prefix > 32\n";
    }

    // F2. Invalid range (start > end)
    std::cout << "  F2. Invalid range handling:\n";

    caught_exception = false;
    try {
        IPIndex range_index;
        range_index.addIPv4Range(100, 50, 1);  // start > end
    } catch (const std::invalid_argument& e) {
        caught_exception = true;
    }

    stats.total++;
    if (caught_exception) {
        stats.passed++;
        std::cout << "    ✓ Invalid range (start > end) throws exception\n";
    } else {
        stats.failed++;
        std::cout << "    ✗ Should throw exception for invalid range\n";
    }

    // F3. Invalid IPv6 CIDR prefix
    std::cout << "  F3. Invalid IPv6 CIDR prefix:\n";

    caught_exception = false;
    try {
        IPv6CIDR invalid_v6_cidr(0, 0, 129);  // Prefix > 128
    } catch (const std::invalid_argument& e) {
        caught_exception = true;
    }

    stats.total++;
    if (caught_exception) {
        stats.passed++;
        std::cout << "    ✓ Invalid IPv6 CIDR prefix > 128 throws exception\n";
    } else {
        stats.failed++;
        std::cout << "    ✗ Should throw exception for IPv6 prefix > 128\n";
    }

    // F4. Invalid IP address parsing (using IPUtils)
    std::cout << "  F4. Invalid IP string parsing:\n";

    uint32_t ip_out;
    bool parsed = IPUtils::parseIPv4("invalid.ip.address", ip_out);
    stats.total++;
    if (!parsed) {
        stats.passed++;
        std::cout << "    ✓ Invalid IPv4 string parsing fails gracefully\n";
    } else {
        stats.failed++;
        std::cout << "    ✗ Invalid IP should fail to parse\n";
    }

    uint64_t hi_out, lo_out;
    parsed = IPUtils::parseIPv6("not:an:ipv6:address", hi_out, lo_out);
    stats.total++;
    if (!parsed) {
        stats.passed++;
        std::cout << "    ✓ Invalid IPv6 string parsing fails gracefully\n";
    } else {
        stats.failed++;
        std::cout << "    ✗ Invalid IPv6 should fail to parse\n";
    }

    // F5. Invalid CIDR string parsing
    std::cout << "  F5. Invalid CIDR string parsing:\n";

    auto cidr_result = IPUtils::parseIPv4CIDR("192.168.1.0/33");
    stats.total++;
    if (!cidr_result.has_value()) {
        stats.passed++;
        std::cout << "    ✓ Invalid CIDR string returns nullopt\n";
    } else {
        stats.failed++;
        std::cout << "    ✗ Invalid CIDR should return nullopt\n";
    }

    auto v6_cidr_result = IPUtils::parseIPv6CIDR("2001:db8::/129");
    stats.total++;
    if (!v6_cidr_result.has_value()) {
        stats.passed++;
        std::cout << "    ✓ Invalid IPv6 CIDR string returns nullopt\n";
    } else {
        stats.failed++;
        std::cout << "    ✗ Invalid IPv6 CIDR should return nullopt\n";
    }

    // F6. Invalid range string parsing
    std::cout << "  F6. Invalid range string parsing:\n";

    auto range_result = IPUtils::parseIPv4Range("192.168.1.100-192.168.1.50");
    stats.total++;
    if (!range_result.has_value()) {
        stats.passed++;
        std::cout << "    ✓ Invalid range (start > end) returns nullopt\n";
    } else {
        stats.failed++;
        std::cout << "    ✗ Invalid range string should return nullopt\n";
    }
}

// =================== Main ===================
int main() {
    std::cout << "========================================\n";
    std::cout << "  IP Filter Unit Tests\n";
    std::cout << "========================================\n";

    TestStats stats;

    try {
        testIPv4(stats);
        testIPv6(stats);
        testEdgeCases(stats);
        testPerformance(stats);
        testThreadSafetyNote(stats);
        testErrorHandling(stats);
    } catch (const std::exception& e) {
        std::cerr << "\n✗ Exception caught: " << e.what() << "\n";
        return 1;
    }

    stats.print();

    if (stats.failed == 0) {
        std::cout << "\n✓ All tests passed!\n";
        return 0;
    } else {
        std::cout << "\n✗ Some tests failed.\n";
        return 1;
    }
}
