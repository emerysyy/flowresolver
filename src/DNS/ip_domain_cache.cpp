#include "ip_domain_cache.hpp"
#include <algorithm>

namespace dns {

void IPDomainCache::addMapping(const flow::FlowIP& ip, const std::vector<std::string>& domains, uint32_t ttl) {
    if (domains.empty() || ip.isNil()) {
        return;
    }

    std::lock_guard<std::mutex> lock(mutex_);

    auto now = std::chrono::steady_clock::now();

    if (ip.isV4()) {
        // IPv4
        auto& entry = ipv4Map_[ip.v4];
        entry.domains.insert(domains.begin(), domains.end());
        entry.ttl = ttl;
        entry.stored_at = now;
    } else if (ip.isV6()) {
        // IPv6
        auto key = std::make_pair(ip.v6.hi, ip.v6.lo);
        auto& entry = ipv6Map_[key];
        entry.domains.insert(domains.begin(), domains.end());
        entry.ttl = ttl;
        entry.stored_at = now;
    }
}

std::vector<std::string> IPDomainCache::queryDomains(const flow::FlowIP& ip) {
    if (ip.isNil()) {
        return {};
    }

    std::lock_guard<std::mutex> lock(mutex_);

    if (ip.isV4()) {
        // IPv4
        auto it = ipv4Map_.find(ip.v4);
        if (it != ipv4Map_.end()) {
            // 检查是否过期
            if (it->second.isExpired()) {
                ipv4Map_.erase(it);
                return {};
            }
            return std::vector<std::string>(it->second.domains.begin(), it->second.domains.end());
        }
    } else if (ip.isV6()) {
        // IPv6
        auto key = std::make_pair(ip.v6.hi, ip.v6.lo);
        auto it = ipv6Map_.find(key);
        if (it != ipv6Map_.end()) {
            // 检查是否过期
            if (it->second.isExpired()) {
                ipv6Map_.erase(it);
                return {};
            }
            return std::vector<std::string>(it->second.domains.begin(), it->second.domains.end());
        }
    }

    return {};
}

void IPDomainCache::cleanExpired() {
    std::lock_guard<std::mutex> lock(mutex_);

    // 清理 IPv4 过期条目
    for (auto it = ipv4Map_.begin(); it != ipv4Map_.end();) {
        if (it->second.isExpired()) {
            it = ipv4Map_.erase(it);
        } else {
            ++it;
        }
    }

    // 清理 IPv6 过期条目
    for (auto it = ipv6Map_.begin(); it != ipv6Map_.end();) {
        if (it->second.isExpired()) {
            it = ipv6Map_.erase(it);
        } else {
            ++it;
        }
    }
}

size_t IPDomainCache::size() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return ipv4Map_.size() + ipv6Map_.size();
}

} // namespace dns
