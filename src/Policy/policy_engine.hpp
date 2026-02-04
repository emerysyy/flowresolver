#ifndef policy_engine_hpp
#define policy_engine_hpp

#include <string>
#include <vector>
#include <cstdint>
#include <optional>
#include <algorithm>
#include "../Resolver/ip_addr.hpp"

namespace proto {
    enum class ProtocolType : int;
}

namespace policy {

/**
 * 策略动作
 */
enum class Action {
    None,        // 未匹配策略
    Bypass,      // 放行
    Drop,        // 丢弃
    Redirect,    // 重定向
    Modify       // 修改
};

/**
 * 策略匹配结果
 */
struct MatchResult {
    Action action;
    std::string reason;
    std::optional<flow::IpAddr> redirectIP;  // 重定向目标IP
};

/**
 * 策略匹配条件
 */
struct PolicyRule {
    // 协议类型（Optional表示匹配所有）
    std::optional<proto::ProtocolType> protocol;

    // 源IP（默认为IPv4任意地址）
    flow::IpAddr srcIP;

    // 目标IP（默认为IPv4任意地址）
    flow::IpAddr dstIP;

    // 源端口（0表示匹配所有）
    uint16_t srcPort;

    // 目标端口（0表示匹配所有）
    uint16_t dstPort;

    // 域名列表（空表示匹配所有）
    std::vector<std::string> domains;

    // 动作
    Action action;

    // 优先级（数字越大优先级越高）
    int priority;
};

/**
 * 策略引擎
 */
class PolicyEngine {
public:
    PolicyEngine();
    ~PolicyEngine() = default;

    /**
     * 匹配策略
     *
     * @param protocol 协议类型
     * @param srcIP 源IP
     * @param dstIP 目标IP
     * @param srcPort 源端口
     * @param dstPort 目标端口
     * @param domains 域名列表
     * @return 匹配结果
     */
    MatchResult match(
        proto::ProtocolType protocol,
        const flow::IpAddr& srcIP,
        const flow::IpAddr& dstIP,
        uint16_t srcPort,
        uint16_t dstPort,
        const std::vector<std::string>& domains
    ) const;

    /**
     * 添加策略规则
     */
    void addRule(const PolicyRule& rule);

    /**
     * 清空所有规则
     */
    void clearRules();

    /**
     * 获取规则数量
     */
    size_t getRuleCount() const { return m_rules.size(); }

private:
    /**
     * 检查域名是否匹配（支持通配符）
     */
    bool matchDomain(const std::string& domain, const std::string& pattern) const;

    /**
     * 检查域名列表是否匹配任一模式
     */
    bool matchDomains(const std::vector<std::string>& domains, const std::vector<std::string>& patterns) const;

private:
    std::vector<PolicyRule> m_rules;
};

} // namespace policy

#endif // policy_engine_hpp
