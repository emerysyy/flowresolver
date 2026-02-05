#ifndef IP_DOMAIN_CACHE_HPP
#define IP_DOMAIN_CACHE_HPP

#include <unordered_map>
#include <unordered_set>
#include <vector>
#include <string>
#include <mutex>
#include <chrono>
#include "../Filter/ip_index.h"

namespace dns {

/**
 * @brief IP-Domain 映射条目
 */
struct IPDomainEntry {
    std::unordered_set<std::string> domains;  // 该 IP 对应的所有域名
    uint32_t ttl;                              // TTL（秒）
    std::chrono::steady_clock::time_point stored_at;  // 存储时间

    // 检查是否过期
    bool isExpired() const {
        auto now = std::chrono::steady_clock::now();
        auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(now - stored_at).count();
        return elapsed >= static_cast<int64_t>(ttl);
    }
};

/**
 * @brief IP-Domain 映射缓存
 *
 * 功能：
 * 1. 存储 IP 到域名的映射关系
 * 2. 支持 IPv4 和 IPv6
 * 3. 自动过期清理
 * 4. 线程安全
 */
class IPDomainCache {
public:
    IPDomainCache() = default;

    /**
     * @brief 添加 IP-Domain 映射
     * @param ip FlowIP 对象
     * @param domains 域名列表
     * @param ttl TTL 值（秒）
     */
    void addMapping(const flow::FlowIP& ip, const std::vector<std::string>& domains, uint32_t ttl);

    /**
     * @brief 根据 IP 查询域名列表
     * @param ip FlowIP 对象
     * @return 域名列表，如果未找到或已过期返回空
     */
    std::vector<std::string> queryDomains(const flow::FlowIP& ip);

    /**
     * @brief 清理过期条目
     */
    void cleanExpired();

    /**
     * @brief 获取缓存大小
     */
    size_t size() const;

private:
    // IPv4 映射：uint32_t -> IPDomainEntry
    std::unordered_map<uint32_t, IPDomainEntry> ipv4Map_;

    // IPv6 映射：pair<uint64_t, uint64_t> -> IPDomainEntry
    struct PairHash {
        size_t operator()(const std::pair<uint64_t, uint64_t>& p) const {
            return std::hash<uint64_t>{}(p.first) ^ (std::hash<uint64_t>{}(p.second) << 1);
        }
    };
    std::unordered_map<std::pair<uint64_t, uint64_t>, IPDomainEntry, PairHash> ipv6Map_;

    mutable std::mutex mutex_;
};

} // namespace dns

#endif // IP_DOMAIN_CACHE_HPP
