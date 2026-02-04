#include "policy_engine.hpp"
#include "../Protocol/protocol_detector.hpp"

namespace policy {

PolicyEngine::PolicyEngine() {
    // 默认规则：放行所有流量
    // 优先级为 0，最低优先级
    PolicyRule defaultRule;
    defaultRule.protocol = std::nullopt;
    defaultRule.srcIP = flow::IpAddr::fromV4(0);
    defaultRule.dstIP = flow::IpAddr::fromV4(0);
    defaultRule.srcPort = 0;
    defaultRule.dstPort = 0;
    defaultRule.domains = {};
    defaultRule.action = Action::Bypass;
    defaultRule.priority = 0;

    m_rules.push_back(defaultRule);
}

MatchResult PolicyEngine::match(
    proto::ProtocolType protocol,
    const flow::IpAddr& srcIP,
    const flow::IpAddr& dstIP,
    uint16_t srcPort,
    uint16_t dstPort,
    const std::vector<std::string>& domains
) const {
    // 按优先级从高到低匹配
    for (const auto& rule : m_rules) {
        // 检查协议
        if (rule.protocol.has_value() && rule.protocol.value() != protocol) {
            continue;
        }

        // 检查源IP
        if (rule.srcIP != flow::IpAddr::fromV4(0) && rule.srcIP != srcIP) {
            continue;
        }

        // 检查目标IP
        if (rule.dstIP != flow::IpAddr::fromV4(0) && rule.dstIP != dstIP) {
            continue;
        }

        // 检查源端口
        if (rule.srcPort != 0 && rule.srcPort != srcPort) {
            continue;
        }

        // 检查目标端口
        if (rule.dstPort != 0 && rule.dstPort != dstPort) {
            continue;
        }

        // 检查域名
        if (!rule.domains.empty() && !matchDomains(domains, rule.domains)) {
            continue;
        }

        // 匹配成功
        MatchResult result;
        result.action = rule.action;
        result.reason = "Policy matched";
        result.redirectIP = std::nullopt;

        return result;
    }

    // 没有匹配到规则，返回默认放行
    MatchResult result;
    result.action = Action::Bypass;
    result.reason = "No matching rule, default bypass";
    result.redirectIP = std::nullopt;

    return result;
}

void PolicyEngine::addRule(const PolicyRule& rule) {
    m_rules.push_back(rule);

    // 按优先级排序（从高到低）
    std::sort(m_rules.begin(), m_rules.end(),
        [](const PolicyRule& a, const PolicyRule& b) {
            return a.priority > b.priority;
        });
}

void PolicyEngine::clearRules() {
    m_rules.clear();

    // 重新添加默认规则
    PolicyRule defaultRule;
    defaultRule.protocol = std::nullopt;
    defaultRule.srcIP = flow::IpAddr::fromV4(0);
    defaultRule.dstIP = flow::IpAddr::fromV4(0);
    defaultRule.srcPort = 0;
    defaultRule.dstPort = 0;
    defaultRule.domains = {};
    defaultRule.action = Action::Bypass;
    defaultRule.priority = 0;

    m_rules.push_back(defaultRule);
}

bool PolicyEngine::matchDomain(const std::string& domain, const std::string& pattern) const {
    // 简单的通配符匹配
    // *.example.com 匹配 www.example.com, foo.example.com
    if (pattern[0] == '*') {
        std::string suffix = pattern.substr(1);
        if (domain.length() >= suffix.length()) {
            return domain.compare(domain.length() - suffix.length(), suffix.length(), suffix) == 0;
        }
        return false;
    }

    // 精确匹配
    return domain == pattern;
}

bool PolicyEngine::matchDomains(
    const std::vector<std::string>& domains,
    const std::vector<std::string>& patterns
) const {
    // 如果域名列表为空，返回false（不匹配）
    if (domains.empty()) {
        return false;
    }

    // 检查是否有任一域名匹配任一模式
    for (const auto& domain : domains) {
        for (const auto& pattern : patterns) {
            if (matchDomain(domain, pattern)) {
                return true;
            }
        }
    }

    return false;
}

} // namespace policy
