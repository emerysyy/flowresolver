#ifndef flow_cache_hpp
#define flow_cache_hpp

#include <cstdint>
#include <unordered_map>
#include <mutex>
#include <chrono>
#include <functional>
#include "../Filter/ip_index.h"

// 前向声明避免循环依赖
namespace proto {
    enum class ProtocolType : int;
}

namespace flow {

/**
 * 五元组流键
 */
struct FlowKey {
    flow::FlowIP src_ip;        // 源IP
    flow::FlowIP dst_ip;        // 目标IP
    uint16_t src_port;    // 源端口
    uint16_t dst_port;    // 目标端口
    uint8_t  protocol;    // 协议 (TCP=6, UDP=17)

    bool operator==(const FlowKey& other) const {
        return src_ip == other.src_ip &&
               dst_ip == other.dst_ip &&
               src_port == other.src_port &&
               dst_port == other.dst_port &&
               protocol == other.protocol;
    }
};

/**
 * FlowKey 哈希函数
 * 使用组合哈希（boost::hash_combine 风格）
 */
struct FlowKeyHash {
    size_t operator()(const FlowKey& key) const {
        size_t h1 = std::hash<flow::FlowIP>{}(key.src_ip);
        size_t h2 = std::hash<flow::FlowIP>{}(key.dst_ip);
        size_t h3 = std::hash<uint16_t>{}(key.src_port);
        size_t h4 = std::hash<uint16_t>{}(key.dst_port);
        size_t h5 = std::hash<uint8_t>{}(key.protocol);

        // 组合哈希
        size_t seed = h1;
        seed ^= h2 + 0x9e3779b9 + (seed << 6) + (seed >> 2);
        seed ^= h3 + 0x9e3779b9 + (seed << 6) + (seed >> 2);
        seed ^= h4 + 0x9e3779b9 + (seed << 6) + (seed >> 2);
        seed ^= h5 + 0x9e3779b9 + (seed << 6) + (seed >> 2);
        return seed;
    }
};

/**
 * 流缓存条目
 */
struct FlowCacheEntry {
    proto::ProtocolType protocol;
    std::chrono::steady_clock::time_point last_seen;

    FlowCacheEntry();
    explicit FlowCacheEntry(proto::ProtocolType p);
};

/**
 * 流协议缓存
 *
 * 功能:
 * - 缓存已识别的协议类型，避免重复检测
 * - 线程安全
 * - 自动过期（默认 60 秒）
 */
class FlowCache {
public:
    /**
     * 构造函数
     * @param ttl 缓存过期时间（秒），默认 300 秒
     * @param max_size 最大缓存条目数，默认 10000
     */
    explicit FlowCache(uint32_t ttl = 300, size_t max_size = 10000);

    ~FlowCache() = default;

    /**
     * 查找流缓存
     * @param key 流键
     * @return 协议类型，如果未找到返回 Unknown
     */
    proto::ProtocolType lookup(const FlowKey& key);

    /**
     * 更新流缓存
     * @param key 流键
     * @param protocol 协议类型
     */
    void update(const FlowKey& key, proto::ProtocolType protocol);

    /**
     * 清理过期条目
     */
    void cleanup();

    /**
     * 清空缓存
     */
    void clear();

    /**
     * 获取缓存统计信息
     */
    struct Stats {
        size_t hits;
        size_t misses;
        size_t size;
        double hit_rate;
    };

    Stats get_stats() const;

private:
    std::unordered_map<FlowKey, FlowCacheEntry, FlowKeyHash> m_cache;
    mutable std::mutex m_mutex;
    uint32_t m_ttl;        // 过期时间（秒）
    size_t m_max_size;     // 最大缓存大小

    // 统计信息
    mutable size_t m_hits = 0;
    mutable size_t m_misses = 0;

    /**
     * 检查条目是否过期
     */
    bool is_expired(const FlowCacheEntry& entry) const;
};

} // namespace flow

#endif // flow_cache_hpp
