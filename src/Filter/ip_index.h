#pragma once

#include "filter_common.h"
#include <vector>
#include <unordered_map>
#include <memory>
#include <cassert>
#include <algorithm>
#include <iostream>
#include <stdexcept>
#include <string>
#include <optional>
#include <tuple>
#include <array>
#include <cstring>
#include <cstdlib>
#include <cstdio>
#include <charconv>
#include <strings.h>
#include <arpa/inet.h>

namespace flow
{
    // ================= 高性能 BitSet =================
    /**
     * @brief 基于排序向量的 BitSet 实现，支持高效合并
     *
     * 设计思路：
     * - 小数据量(<32): 使用 sorted vector，插入/合并开销可接受
     * - 中等数据量: batch insert 减少重复排序
     * - 大数据量: 考虑迁移到 bitmap
     */
    class BitSet
    {
    public:
        BitSet() { m_vec.reserve(8); }

        void set(RuleId id)
        {
            auto it = std::lower_bound(m_vec.begin(), m_vec.end(), id);
            if (it == m_vec.end() || *it != id)
            {
                m_vec.insert(it, id);
            }
        }

        void setBatch(const std::vector<RuleId> &ids)
        {
            if (ids.empty())
                return;

            // 预分配空间
            m_vec.reserve(m_vec.size() + ids.size());

            // 批量插入后一次性排序去重（比 inplace_merge 更快）
            m_vec.insert(m_vec.end(), ids.begin(), ids.end());
            std::sort(m_vec.begin(), m_vec.end());
            m_vec.erase(std::unique(m_vec.begin(), m_vec.end()), m_vec.end());
        }

        void merge(const BitSet &other)
        {
            if (other.empty())
                return;
            if (empty())
            {
                m_vec = other.m_vec;
                return;
            }

            std::vector<RuleId> tmp;
            tmp.reserve(m_vec.size() + other.m_vec.size());
            std::set_union(m_vec.begin(), m_vec.end(),
                           other.m_vec.begin(), other.m_vec.end(),
                           std::back_inserter(tmp));
            m_vec.swap(tmp);
        }

        void merge(BitSet &&other) noexcept
        {
            if (other.empty())
                return;
            if (empty())
            {
                m_vec = std::move(other.m_vec);
                return;
            }

            std::vector<RuleId> tmp;
            tmp.reserve(m_vec.size() + other.m_vec.size());
            std::set_union(m_vec.begin(), m_vec.end(),
                           other.m_vec.begin(), other.m_vec.end(),
                           std::back_inserter(tmp));
            m_vec.swap(tmp);
        }

        void clear() noexcept { m_vec.clear(); }
        [[nodiscard]] bool empty() const noexcept { return m_vec.empty(); }
        [[nodiscard]] size_t size() const noexcept { return m_vec.size(); }
        [[nodiscard]] const std::vector<RuleId> &values() const noexcept { return m_vec; }

        auto begin() const noexcept { return m_vec.begin(); }
        auto end() const noexcept { return m_vec.end(); }

    private:
        std::vector<RuleId> m_vec;
    };

    // ================= IPv4/IPv6 地址抽象 =================
    /**
     * @brief 统一的流量 IP 地址表示
     *
     * 特性：
     * - 自动处理 IPv4-mapped IPv6 (::ffff:0:0/96)
     * - 零拷贝设计
     * - 支持空地址表示
     */
    struct FlowIP
    {
        enum class Kind : uint8_t
        {
            Nil,
            V4,
            V6
        };
        Kind kind;

        union
        {
            uint32_t v4;
            struct
            {
                uint64_t hi, lo;
            } v6;
        };

        FlowIP() : kind(Kind::Nil), v4(0) {}

        static FlowIP fromIPv4(uint32_t ip)
        {
            FlowIP f;
            f.kind = Kind::V4;
            f.v4 = ip;
            return f;
        }

        static FlowIP fromIPv6(uint64_t hi, uint64_t lo)
        {
            FlowIP f;

            // 检测 IPv4-mapped: ::ffff:a.b.c.d
            if (hi == 0 && ((lo >> 32) == 0x0000FFFF))
            {
                f.kind = Kind::V4;
                f.v4 = static_cast<uint32_t>(lo & 0xFFFFFFFFULL);
            }
            else
            {
                f.kind = Kind::V6;
                f.v6.hi = hi;
                f.v6.lo = lo;
            }
            return f;
        }

        bool isNil() const noexcept { return kind == Kind::Nil; }
        bool isV4() const noexcept { return kind == Kind::V4; }
        bool isV6() const noexcept { return kind == Kind::V6; }
        
        bool operator==(const FlowIP &other) const
        {
            if (kind != other.kind)
                return false;
            if (kind == FlowIP::Kind::V4)
                return this->v4 == other.v4;
            return this->v6.hi == other.v6.hi && this->v6.lo == other.v6.lo;
        }

        bool operator!=(const FlowIP &other) const
        {
            return !(*this == other);
        }
    };

    // ================= CIDR 表示 =================
    // 192.168.1.1/16
    struct IPv4CIDR
    {
        uint32_t network;
        uint8_t prefix;

        IPv4CIDR(uint32_t ip, uint8_t pre) : prefix(pre)
        {
            if (pre > 32)
            {
                throw std::invalid_argument("IPv4 prefix must be <= 32");
            }
            // 规范化网络地址
            if (pre == 0)
            {
                network = 0;
            }
            else
            {
                uint32_t mask = ~((1u << (32 - pre)) - 1);
                network = ip & mask;
            }
        }
    };

    struct IPv6CIDR
    {
        uint64_t hi, lo;
        uint8_t prefix;

        IPv6CIDR(uint64_t h, uint64_t l, uint8_t pre) : prefix(pre)
        {
            if (pre > 128)
            {
                throw std::invalid_argument("IPv6 prefix must be <= 128");
            }

            // 规范化网络地址
            if (pre == 0)
            {
                hi = lo = 0;
            }
            else if (pre < 64)
            {
                // 注意：1ULL << 64 是未定义行为，所以用 < 而非 <=
                uint64_t mask = ~((1ULL << (64 - pre)) - 1);
                hi = h & mask;
                lo = 0;
            }
            else if (pre == 64)
            {
                hi = h;
                lo = 0;
            }
            else if (pre < 128)
            {
                hi = h;
                uint64_t shift = 128 - pre; // 1-63
                uint64_t mask = ~((1ULL << shift) - 1);
                lo = l & mask;
            }
            else
            { // pre == 128
                hi = h;
                lo = l;
            }
        }

        // 转换为 128 位整数（用于比较）
        struct UInt128
        {
            uint64_t hi, lo;

            bool operator<(const UInt128 &other) const noexcept
            {
                return hi < other.hi || (hi == other.hi && lo < other.lo);
            }
            bool operator<=(const UInt128 &other) const noexcept
            {
                return !(other < *this);
            }
            bool operator>(const UInt128 &other) const noexcept
            {
                return other < *this;
            }
            bool operator>=(const UInt128 &other) const noexcept
            {
                return !(*this < other);
            }
            bool operator==(const UInt128 &other) const noexcept
            {
                return hi == other.hi && lo == other.lo;
            }
            bool operator!=(const UInt128 &other) const noexcept
            {
                return !(*this == other);
            }
        };

        UInt128 asUInt128() const noexcept { return {hi, lo}; }
    };

    // ================= IPRange 表示 =================
    // 192.168.1.1-192.168.1.10
    struct IPv4Range
    {
        uint32_t start;
        uint32_t end;
    };

    struct IPv6Range
    {
        uint64_t hi_start;
        uint64_t lo_start;
        uint64_t hi_end;
        uint64_t lo_end;
    };

    // ================= IPKind 表示 =================
    enum IPKind
    {
        ExactV4,
        CIDRV4,
        RangeV4,
        ExactV6,
        CIDRV6,
        RangeV6
    };
};

// 提供哈希支持
namespace std
{
    template <>
    struct hash<flow::IPv6CIDR::UInt128>
    {
        size_t operator()(const flow::IPv6CIDR::UInt128 &x) const noexcept
        {
            return std::hash<uint64_t>{}(x.hi) ^ (std::hash<uint64_t>{}(x.lo) << 1);
        }
    };


    template<>
    struct hash<flow::FlowIP> {
        size_t operator()(const flow::FlowIP& ip) const {
            switch (ip.kind)
            {
                case flow::FlowIP::Kind::Nil:
                    return 0;
                case flow::FlowIP::Kind::V4:
                    return std::hash<uint32_t>{}(ip.v4);
                case flow::FlowIP::Kind::V6:
                {
                    // 混合高低64位生成 size_t 哈希
                    size_t h1 = std::hash<uint64_t>{}(ip.v6.hi);
                    size_t h2 = std::hash<uint64_t>{}(ip.v6.lo);
                    // 简单异或并混合位
                    return h1 ^ (h2 + 0x9e3779b9 + (h1 << 6) + (h1 >> 2));
                }
            }
            return 0; // 避免编译警告
        }
    };

}

namespace flow
{

    // ================= 增强的区间树 =================
    /**
     * @brief 基于 AVL 平衡的区间树
     *
     * 优化点：
     * - 自动平衡，避免退化
     * - 精确的查询剪枝
     * - 延迟规则合并
     */
    template <typename T>
    class IntervalTree
    {
    public:
        struct Node
        {
            T start, end, maxEnd;
            BitSet rules;
            std::unique_ptr<Node> left, right;
            int height;

            Node(T s, T e, RuleId id)
                : start(s), end(e), maxEnd(e), height(1)
            {
                rules.set(id);
            }
        };

        IntervalTree() : root(nullptr) {}

        void add(T start, T end, RuleId id)
        {
            if (start > end)
            {
                throw std::invalid_argument("Invalid interval: start > end");
            }
            root = insert(std::move(root), start, end, id);
        }

        void query(T val, BitSet &out) const
        {
            queryNode(root.get(), val, out);
        }

        BitSet query(T val) const
        {
            BitSet result;
            query(val, result);
            return result;
        }

    private:
        std::unique_ptr<Node> root;

        int height(Node *n) const { return n ? n->height : 0; }

        int balanceFactor(Node *n) const
        {
            return n ? height(n->left.get()) - height(n->right.get()) : 0;
        }

        void updateHeight(Node *n)
        {
            if (n)
            {
                n->height = 1 + std::max(height(n->left.get()), height(n->right.get()));
                n->maxEnd = n->end;
                if (n->left)
                    n->maxEnd = std::max(n->maxEnd, n->left->maxEnd);
                if (n->right)
                    n->maxEnd = std::max(n->maxEnd, n->right->maxEnd);
            }
        }

        std::unique_ptr<Node> rotateRight(std::unique_ptr<Node> y)
        {
            auto x = std::move(y->left);
            y->left = std::move(x->right);
            updateHeight(y.get());
            x->right = std::move(y);
            updateHeight(x.get());
            return x;
        }

        std::unique_ptr<Node> rotateLeft(std::unique_ptr<Node> x)
        {
            auto y = std::move(x->right);
            x->right = std::move(y->left);
            updateHeight(x.get());
            y->left = std::move(x);
            updateHeight(y.get());
            return y;
        }

        std::unique_ptr<Node> balance(std::unique_ptr<Node> node)
        {
            updateHeight(node.get());
            int bf = balanceFactor(node.get());

            // Left-heavy
            if (bf > 1)
            {
                if (balanceFactor(node->left.get()) < 0)
                {
                    node->left = rotateLeft(std::move(node->left));
                }
                return rotateRight(std::move(node));
            }

            // Right-heavy
            if (bf < -1)
            {
                if (balanceFactor(node->right.get()) > 0)
                {
                    node->right = rotateRight(std::move(node->right));
                }
                return rotateLeft(std::move(node));
            }

            return node;
        }

        std::unique_ptr<Node> insert(std::unique_ptr<Node> node, T s, T e, RuleId id)
        {
            if (!node)
            {
                return std::make_unique<Node>(s, e, id);
            }

            // 相同区间合并规则
            if (s == node->start && e == node->end)
            {
                node->rules.set(id);
                return node;
            }

            if (s < node->start || (s == node->start && e < node->end))
            {
                node->left = insert(std::move(node->left), s, e, id);
            }
            else
            {
                node->right = insert(std::move(node->right), s, e, id);
            }

            return balance(std::move(node));
        }

        void queryNode(Node *node, T val, BitSet &out) const
        {
            if (!node)
                return;

            // 当前节点包含查询值
            if (val >= node->start && val <= node->end)
            {
                out.merge(node->rules);
            }

            // 左子树可能包含
            if (node->left && val <= node->left->maxEnd)
            {
                queryNode(node->left.get(), val, out);
            }

            // 右子树剪枝：由于右子树所有区间的 start >= node->start
            // 所以需要 val >= node->start 才可能有交集
            if (node->right && val >= node->start && val <= node->right->maxEnd)
            {
                queryNode(node->right.get(), val, out);
            }
        }
    };

    // ================= Patricia Trie =================
    /**
     * @brief 用于 CIDR 匹配的 Patricia Trie
     *
     * 支持：
     * - 所有前缀匹配
     * - 最长前缀匹配（LPM）
     */
    template <typename KeyType, int BITS>
    class PatriciaTrie
    {
    public:
        struct Node
        {
            BitSet rules;
            std::unique_ptr<Node> children[2];

            Node() : children{nullptr, nullptr} {}
        };

        PatriciaTrie() : root(std::make_unique<Node>()) {}

        void insert(KeyType key, int prefixLen, RuleId id)
        {
            if (prefixLen < 0 || prefixLen > BITS)
            {
                throw std::invalid_argument("Invalid prefix length");
            }

            Node *node = root.get();
            for (int i = BITS - 1; i >= BITS - prefixLen; --i)
            {
                int bit = (key >> i) & 1;
                if (!node->children[bit])
                {
                    node->children[bit] = std::make_unique<Node>();
                }
                node = node->children[bit].get();
            }
            node->rules.set(id);
        }

        // 匹配所有覆盖该地址的 CIDR
        void matchAll(KeyType key, BitSet &out) const
        {
            Node *node = root.get();
            out.merge(node->rules); // 根节点代表 0.0.0.0/0

            for (int i = BITS - 1; i >= 0 && node; --i)
            {
                int bit = (key >> i) & 1;
                node = node->children[bit].get();
                if (node)
                {
                    out.merge(node->rules);
                }
            }
        }

        // 最长前缀匹配
        void matchLongest(KeyType key, BitSet &out) const
        {
            Node *node = root.get();
            Node *lastMatch = nullptr;

            if (!node->rules.empty())
            {
                lastMatch = node;
            }

            for (int i = BITS - 1; i >= 0 && node; --i)
            {
                int bit = (key >> i) & 1;
                node = node->children[bit].get();
                if (node && !node->rules.empty())
                {
                    lastMatch = node;
                }
            }

            if (lastMatch)
            {
                out.merge(lastMatch->rules);
            }
        }

    private:
        std::unique_ptr<Node> root;
    };

    // ================= IPv6 Trie（避免 __uint128_t） =================
    /**
     * @brief 128 位 Patricia Trie，不依赖编译器扩展
     */
    class IPv6Trie
    {
    public:
        struct Node
        {
            BitSet rules;
            std::unique_ptr<Node> children[2];

            Node() : children{nullptr, nullptr} {}
        };

        IPv6Trie() : root(std::make_unique<Node>()) {}

        void insert(uint64_t hi, uint64_t lo, int prefixLen, RuleId id)
        {
            if (prefixLen < 0 || prefixLen > 128)
            {
                throw std::invalid_argument("Invalid IPv6 prefix length");
            }

            Node *node = root.get();

            for (int i = 127; i >= 128 - prefixLen; --i)
            {
                int bit;
                if (i >= 64)
                {
                    bit = (hi >> (i - 64)) & 1;
                }
                else
                {
                    bit = (lo >> i) & 1;
                }

                if (!node->children[bit])
                {
                    node->children[bit] = std::make_unique<Node>();
                }
                node = node->children[bit].get();
            }
            node->rules.set(id);
        }

        void matchAll(uint64_t hi, uint64_t lo, BitSet &out) const
        {
            Node *node = root.get();
            out.merge(node->rules);

            for (int i = 127; i >= 0 && node; --i)
            {
                int bit;
                if (i >= 64)
                {
                    bit = (hi >> (i - 64)) & 1;
                }
                else
                {
                    bit = (lo >> i) & 1;
                }

                node = node->children[bit].get();
                if (node)
                {
                    out.merge(node->rules);
                }
            }
        }

        void matchLongest(uint64_t hi, uint64_t lo, BitSet &out) const
        {
            Node *node = root.get();
            Node *lastMatch = !node->rules.empty() ? node : nullptr;

            for (int i = 127; i >= 0 && node; --i)
            {
                int bit;
                if (i >= 64)
                {
                    bit = (hi >> (i - 64)) & 1;
                }
                else
                {
                    bit = (lo >> i) & 1;
                }

                node = node->children[bit].get();
                if (node && !node->rules.empty())
                {
                    lastMatch = node;
                }
            }

            if (lastMatch)
            {
                out.merge(lastMatch->rules);
            }
        }

    private:
        std::unique_ptr<Node> root;
    };

    // ================= IP 索引（核心匹配引擎） =================
    /**
     * @brief 统一的 IP 规则匹配索引
     *
     * 支持：
     * - 精确匹配
     * - CIDR 匹配
     * - 区间匹配
     * - IPv4-mapped IPv6 透明处理
     */
    class IPIndex
    {
    public:
        enum class MatchMode
        {
            All,    // 匹配所有规则
            Longest // 最长前缀匹配（仅 CIDR）
        };

        void addIPv4Exact(uint32_t ip, RuleId id)
        {
            exactIPv4[ip].set(id);
        }

        void addIPv6Exact(uint64_t hi, uint64_t lo, RuleId id)
        {
            exactIPv6[{hi, lo}].set(id);
        }

        void addIPv4CIDR(const IPv4CIDR &cidr, RuleId id)
        {
            trieIPv4.insert(cidr.network, cidr.prefix, id);
        }

        void addIPv6CIDR(const IPv6CIDR &cidr, RuleId id)
        {
            trieIPv6.insert(cidr.hi, cidr.lo, cidr.prefix, id);
        }

        void addIPv4Range(uint32_t start, uint32_t end, RuleId id)
        {
            rangeIPv4.add(start, end, id);
        }

        void addIPv6Range(uint64_t hiStart, uint64_t loStart,
                          uint64_t hiEnd, uint64_t loEnd, RuleId id)
        {
            rangeIPv6.add({hiStart, loStart}, {hiEnd, loEnd}, id);
        }

        void addNil(RuleId id)
        {
            nilIP.set(id);
        }

        // ========== 查询 ==========

        std::vector<RuleId> queryIds(const FlowIP &flow, MatchMode mode = MatchMode::All) const
        {
            BitSet bitset_result;
            query(flow, bitset_result, mode);
            return bitset_result.values();
        }

        BitSet query(const FlowIP &flow, MatchMode mode = MatchMode::All) const
        {
            BitSet result;
            query(flow, result, mode);
            return result;
        }

        void query(const FlowIP &flow, BitSet &out, MatchMode mode = MatchMode::All) const
        {
            switch (flow.kind)
            {
            case FlowIP::Kind::V4:
                queryIPv4(flow.v4, out, mode);
                break;
            case FlowIP::Kind::V6:
                queryIPv6(flow.v6.hi, flow.v6.lo, out, mode);
                break;
            case FlowIP::Kind::Nil:
                out.merge(nilIP);
                break;
            }
        }

        // 统计信息
        struct Stats
        {
            size_t exactIPv4Count = 0;
            size_t exactIPv6Count = 0;
            size_t totalRules = 0;
        };

        Stats getStats() const
        {
            Stats s;
            s.exactIPv4Count = exactIPv4.size();
            s.exactIPv6Count = exactIPv6.size();
            // TODO: 统计 trie 和 range 中的规则数
            return s;
        }

    private:
        // IPv4 索引
        std::unordered_map<uint32_t, BitSet> exactIPv4;
        PatriciaTrie<uint32_t, 32> trieIPv4;
        IntervalTree<uint32_t> rangeIPv4;

        // IPv6 索引
        struct PairHash
        {
            size_t operator()(const std::pair<uint64_t, uint64_t> &p) const
            {
                return std::hash<uint64_t>{}(p.first) ^
                       (std::hash<uint64_t>{}(p.second) << 1);
            }
        };
        std::unordered_map<std::pair<uint64_t, uint64_t>, BitSet, PairHash> exactIPv6;
        IPv6Trie trieIPv6;
        IntervalTree<IPv6CIDR::UInt128> rangeIPv6;

        BitSet nilIP;

        void queryIPv4(uint32_t ip, BitSet &out, MatchMode mode) const
        {
            // 精确匹配
            auto it = exactIPv4.find(ip);
            if (it != exactIPv4.end())
            {
                out.merge(it->second);
            }

            // CIDR 匹配
            if (mode == MatchMode::All)
            {
                trieIPv4.matchAll(ip, out);
            }
            else
            {
                trieIPv4.matchLongest(ip, out);
            }

            // 区间匹配
            rangeIPv4.query(ip, out);
        }

        void queryIPv6(uint64_t hi, uint64_t lo, BitSet &out, MatchMode mode) const
        {
            // 精确匹配
            auto it = exactIPv6.find({hi, lo});
            if (it != exactIPv6.end())
            {
                out.merge(it->second);
            }

            // CIDR 匹配
            if (mode == MatchMode::All)
            {
                trieIPv6.matchAll(hi, lo, out);
            }
            else
            {
                trieIPv6.matchLongest(hi, lo, out);
            }

            // 区间匹配
            IPv6CIDR::UInt128 key{hi, lo};
            rangeIPv6.query(key, out);
        }
    };

    // ================= 辅助函数 =================
    namespace IPUtils
    {

        // ================= IPv4 =================
        inline bool parseIPv4(const char *str, uint32_t &out)
        {
            struct sockaddr_in sa{};
            if (inet_pton(AF_INET, str, &sa.sin_addr) != 1)
                return false;
            out = ntohl(sa.sin_addr.s_addr);
            return true;
        }

        inline std::string formatIPv4(uint32_t ip)
        {
            struct in_addr addr{};
            addr.s_addr = htonl(ip);
            char buf[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &addr, buf, sizeof(buf));
            return buf;
        }

        inline std::optional<IPv4Range> parseIPv4Range(const char *str)
        {
            std::string s(str);
            auto pos = s.find('-');
            if (pos == std::string::npos)
                return std::nullopt;
            uint32_t start{}, end{};
            if (!parseIPv4(s.substr(0, pos).c_str(), start))
                return std::nullopt;
            if (!parseIPv4(s.substr(pos + 1).c_str(), end))
                return std::nullopt;
            if (start > end)
                return std::nullopt;
            return IPv4Range{start, end};
        }

        inline std::optional<IPv4CIDR> parseIPv4CIDR(const char *str)
        {
            std::string s(str);
            auto pos = s.find('/');
            if (pos == std::string::npos)
                return std::nullopt;

            uint32_t ip{};
            if (!parseIPv4(s.substr(0, pos).c_str(), ip))
                return std::nullopt;

            int prefix{};
            auto [ptr, ec] = std::from_chars(s.data() + pos + 1, s.data() + s.size(), prefix);
            if (ec != std::errc() || prefix < 0 || prefix > 32)
                return std::nullopt;

            if (prefix < 32)
                ip &= ~((1u << (32 - prefix)) - 1);
            else if (prefix == 0)
                ip = 0;

            return IPv4CIDR{ip, static_cast<uint8_t>(prefix)};
        }

        // ================= IPv6 =================

        inline bool parseIPv6(const char *str, uint64_t &hi, uint64_t &lo)
        {
            struct in6_addr addr6{};
            if (inet_pton(AF_INET6, str, &addr6) != 1)
                return false;

            hi = 0;
            lo = 0;
            for (int i = 0; i < 8; ++i)
                hi = (hi << 8) | addr6.s6_addr[i];
            for (int i = 8; i < 16; ++i)
                lo = (lo << 8) | addr6.s6_addr[i];
            return true;
        }

        inline std::string formatIPv6(uint64_t hi, uint64_t lo)
        {
            struct in6_addr addr6{};
            for (int i = 0; i < 8; ++i)
                addr6.s6_addr[i] = (hi >> (56 - 8 * i)) & 0xFF;
            for (int i = 0; i < 8; ++i)
                addr6.s6_addr[8 + i] = (lo >> (56 - 8 * i)) & 0xFF;
            char buf[INET6_ADDRSTRLEN];
            inet_ntop(AF_INET6, &addr6, buf, sizeof(buf));
            return buf;
        }

        inline std::optional<IPv6Range> parseIPv6Range(const char *str)
        {
            std::string s(str);
            auto pos = s.find('-');
            if (pos == std::string::npos)
                return std::nullopt;

            uint64_t hs{}, ls{}, he{}, le{};
            if (!parseIPv6(s.substr(0, pos).c_str(), hs, ls))
                return std::nullopt;
            if (!parseIPv6(s.substr(pos + 1).c_str(), he, le))
                return std::nullopt;

            __uint128_t start = (__uint128_t(hs) << 64) | ls;
            __uint128_t end = (__uint128_t(he) << 64) | le;
            if (start > end)
                return std::nullopt;

            return IPv6Range{hs, ls, he, le};
        }

        inline std::optional<IPv6CIDR> parseIPv6CIDR(const char *str)
        {
            std::string s(str);
            auto pos = s.find('/');
            if (pos == std::string::npos)
                return std::nullopt;

            uint64_t hi{}, lo{};
            if (!parseIPv6(s.substr(0, pos).c_str(), hi, lo))
                return std::nullopt;

            int prefix{};
            auto [ptr, ec] = std::from_chars(s.data() + pos + 1, s.data() + s.size(), prefix);
            if (ec != std::errc() || prefix < 0 || prefix > 128)
                return std::nullopt;

            if (prefix < 64)
                hi &= ~((1ULL << (64 - prefix)) - 1), lo = 0;
            else if (prefix == 64)
                lo = 0;
            else if (prefix < 128)
                lo &= ~((1ULL << (128 - prefix)) - 1);
            // pre == 128 保持不变

            return IPv6CIDR{hi, lo, static_cast<uint8_t>(prefix)};
        }
        // ================= ParsedIP =================
        struct ParsedIP
        {
            IPKind kind;

            // IPv4
            uint32_t v4{0};
            IPv4CIDR v4_cidr{0, 0};
            IPv4Range v4_range{0, 0};

            // IPv6
            uint64_t v6_hi{0}, v6_lo{0};
            IPv6CIDR v6_cidr{0, 0, 0};
            IPv6Range v6_range{0, 0, 0, 0};

            ParsedIP(IPKind k) : kind(k) {}
        };

        // ================= 自动解析 =================
        inline IPKind detectIPKind(const char *str)
        {
            return std::strchr(str, ':') ? IPKind::ExactV6 : IPKind::ExactV4;
        }

        inline std::optional<ParsedIP> parseIPAuto(const char *str)
        {
            std::string s(str);

            // CIDR
            auto pos_cidr = s.find('/');
            if (pos_cidr != std::string::npos)
            {
                if (s.find(':') != std::string::npos) // IPv6 CIDR
                {
                    if (auto cidr = parseIPv6CIDR(str))
                    {
                        ParsedIP p(IPKind::CIDRV6);
                        p.v6_cidr = *cidr;
                        return p;
                    }
                }
                else // IPv4 CIDR
                {
                    if (auto cidr = parseIPv4CIDR(str))
                    {
                        ParsedIP p(IPKind::CIDRV4);
                        p.v4_cidr = *cidr;
                        return p;
                    }
                }
            }

            // Range
            auto pos_range = s.find('-');
            if (pos_range != std::string::npos)
            {
                if (s.find(':') != std::string::npos) // IPv6 Range
                {
                    if (auto r = parseIPv6Range(str))
                    {
                        ParsedIP p(IPKind::RangeV6);
                        p.v6_range = *r;
                        return p;
                    }
                }
                else // IPv4 Range
                {
                    if (auto r = parseIPv4Range(str))
                    {
                        ParsedIP p(IPKind::RangeV4);
                        p.v4_range = *r;
                        return p;
                    }
                }
            }

            // Exact
            if (s.find(':') != std::string::npos) // IPv6
            {
                uint64_t hi{}, lo{};
                if (!parseIPv6(str, hi, lo))
                    return std::nullopt;
                ParsedIP p(IPKind::ExactV6);
                p.v6_hi = hi;
                p.v6_lo = lo;
                return p;
            }
            else // IPv4
            {
                uint32_t ip{};
                if (!parseIPv4(str, ip))
                    return std::nullopt;
                ParsedIP p(IPKind::ExactV4);
                p.v4 = ip;
                return p;
            }
        }

    } // namespace IPUtils

};
