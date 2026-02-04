#include "flow_cache.hpp"
#include "../Protocol/protocol_detector.hpp"

namespace flow {

// FlowCacheEntry 构造函数
FlowCacheEntry::FlowCacheEntry()
    : protocol(static_cast<proto::ProtocolType>(0)),
      last_seen(std::chrono::steady_clock::now()) {
}

FlowCacheEntry::FlowCacheEntry(proto::ProtocolType p)
    : protocol(p),
      last_seen(std::chrono::steady_clock::now()) {
}

FlowCache::FlowCache(uint32_t ttl, size_t max_size)
    : m_ttl(ttl), m_max_size(max_size) {
}

proto::ProtocolType FlowCache::lookup(const FlowKey& key) {
    std::lock_guard<std::mutex> lock(m_mutex);

    auto it = m_cache.find(key);
    if (it == m_cache.end()) {
        ++m_misses;
        return proto::ProtocolType::Unknown;
    }

    // 检查是否过期
    if (is_expired(it->second)) {
        m_cache.erase(it);
        ++m_misses;
        return proto::ProtocolType::Unknown;
    }

    // 更新最后访问时间
    it->second.last_seen = std::chrono::steady_clock::now();
    ++m_hits;
    return it->second.protocol;
}

void FlowCache::update(const FlowKey& key, proto::ProtocolType protocol) {
    std::lock_guard<std::mutex> lock(m_mutex);

    // 如果缓存已满，清理过期条目
    if (m_cache.size() >= m_max_size) {
        cleanup();
    }

    // 如果仍然已满，删除最旧的条目
    if (m_cache.size() >= m_max_size) {
        auto oldest = m_cache.begin();
        for (auto it = m_cache.begin(); it != m_cache.end(); ++it) {
            if (it->second.last_seen < oldest->second.last_seen) {
                oldest = it;
            }
        }
        if (oldest != m_cache.end()) {
            m_cache.erase(oldest);
        }
    }

    m_cache[key] = FlowCacheEntry(protocol);
}

void FlowCache::cleanup() {
    auto now = std::chrono::steady_clock::now();
    auto ttl = std::chrono::seconds(m_ttl);

    for (auto it = m_cache.begin(); it != m_cache.end(); ) {
        if (now - it->second.last_seen > ttl) {
            it = m_cache.erase(it);
        } else {
            ++it;
        }
    }
}

void FlowCache::clear() {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_cache.clear();
    m_hits = 0;
    m_misses = 0;
}

FlowCache::Stats FlowCache::get_stats() const {
    std::lock_guard<std::mutex> lock(m_mutex);

    Stats stats;
    stats.hits = m_hits;
    stats.misses = m_misses;
    stats.size = m_cache.size();

    size_t total = m_hits + m_misses;
    stats.hit_rate = total > 0 ? static_cast<double>(m_hits) / total : 0.0;

    return stats;
}

bool FlowCache::is_expired(const FlowCacheEntry& entry) const {
    auto now = std::chrono::steady_clock::now();
    auto ttl = std::chrono::seconds(m_ttl);
    return (now - entry.last_seen) > ttl;
}

} // namespace flow
