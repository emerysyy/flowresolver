#include "policy_engine.hpp"
#include "../Protocol/protocol_detector.hpp"
#include <unordered_set>
#include <sstream>

namespace policy {

std::string trim(const std::string& s) {
    size_t start = s.find_first_not_of(" \t\r\n");
    size_t end = s.find_last_not_of(" \t\r\n");
    return (start == std::string::npos) ? "" : s.substr(start, end - start + 1);
}

PolicyEngine::PolicyEngine() {

}

bool PolicyEngine::addPolicy(const Policy& policy) {
    return addPolicyInternal(policy, false);
}

size_t PolicyEngine::addPolicies(const std::vector<Policy>& policies) {
    size_t success_count = 0;

    // 批量添加，延迟rebuild
    for (const auto& policy : policies) {
        if (addPolicyInternal(policy, true)) {
            success_count++;
        }
    }

    // 统一rebuild一次
    if (success_count > 0) {
        rebuildIndex();
    }

    return success_count;
}

bool PolicyEngine::addPolicyInternal(const Policy& policy, bool defer_rebuild) {
    if (policies_.count(policy.rule_id)) {
        return false;
    }

    flow::FlowIP ip;
    flow::IPv4CIDR v4_cidr(0, 0);
    flow::IPv4Range v4_range{0, 0};
    flow::IPv6CIDR v6_cidr(0, 0, 0);
    flow::IPv6Range v6_range{0, 0, 0, 0};

    if (!parseAddress(policy.address, ip, v4_cidr, v4_range, v6_cidr, v6_range)) {
        return false;
    }

    // 添加到 IP 索引
    // 注意：不能依赖 ip.isV4()/isV6() 因为 CIDR/Range 不会设置 ip 的类型
    // 必须直接检查 address 字符串

    // IPv4 类型规则
    if (policy.address.find('/') != std::string::npos &&
        policy.address.find(':') == std::string::npos) {
        // IPv4 CIDR
        ip_index_.addIPv4CIDR(v4_cidr, policy.rule_id);
    } else if (policy.address.find('-') != std::string::npos &&
               policy.address.find(':') == std::string::npos) {
        // IPv4 Range
        ip_index_.addIPv4Range(v4_range.start, v4_range.end, policy.rule_id);
    } else if (ip.isV4()) {
        // IPv4 精确匹配
        ip_index_.addIPv4Exact(ip.v4, policy.rule_id);
    }

    // IPv6 类型规则
    if (policy.address.find('/') != std::string::npos &&
        policy.address.find(':') != std::string::npos) {
        // IPv6 CIDR
        ip_index_.addIPv6CIDR(v6_cidr, policy.rule_id);
    } else if (policy.address.find('-') != std::string::npos &&
               policy.address.find(':') != std::string::npos) {
        // IPv6 Range
        ip_index_.addIPv6Range(v6_range.hi_start, v6_range.lo_start,
                               v6_range.hi_end, v6_range.lo_end, policy.rule_id);
    } else if (ip.isV6()) {
        // IPv6 精确匹配
        ip_index_.addIPv6Exact(ip.v6.hi, ip.v6.lo, policy.rule_id);
    }

    // ===== 端口处理 =====
    std::vector<flow::PortMatcher::Rule> portRules;
    if (parsePortString(policy.port, policy.rule_id, portRules))
    {
        port_rules_.insert(port_rules_.end(), portRules.begin(), portRules.end());
        // 只在非延迟模式下rebuild
        if (!defer_rebuild) {
            rebuildPortMatcher();
        }
    }


    // 域名处理
    if (!policy.address.empty() && (policy.address.find('.') != std::string::npos ||
                                   policy.address[0] == '*')) {
        flow::DomainRule domain_rule{policy.rule_id, policy.address};
        domain_matcher_.addRule(domain_rule);

        // 将域名规则也添加到 IP 索引的 Nil 集合中
        // 这样当 dstIP 为空（Kind::Nil）时，仍能匹配到域名规则
        ip_index_.addNil(policy.rule_id);
    }

    policies_[policy.rule_id] = policy;
    return true;
}

void PolicyEngine::rebuildIndex() {
    rebuildPortMatcher();
}

void PolicyEngine::rebuildPortMatcher() {
    if (!port_rules_.empty()) {
        port_matcher_.rebuild(port_rules_);
    }
}

bool PolicyEngine::removePolicy(flow::RuleId rule_id) {
    auto it = policies_.find(rule_id);
    if (it == policies_.end()) {
        return false;
    }

    // 移除域名规则
    domain_matcher_.removeRule(rule_id);

    // 移除端口规则
    port_rules_.erase(
        std::remove_if(port_rules_.begin(), port_rules_.end(),
                      [rule_id](const flow::PortMatcher::Rule& r) {
                          return r.ruleId == rule_id;
                      }),
        port_rules_.end());

    // 重建端口匹配器
    rebuildPortMatcher();

    policies_.erase(it);
    return true;
}

void PolicyEngine::clear() {
    ip_index_ = flow::IPIndex{};
    domain_matcher_.clear();
    port_rules_.clear();
    policies_.clear();
    rebuildPortMatcher();
}

size_t PolicyEngine::getPolicyCount() const {
    return policies_.size();
}
std::unordered_set<flow::RuleId> PolicyEngine::match(proto::ProtocolType protocol,
                                const flow::FlowIP& dstIP,
                                uint16_t dstPort,
                                const std::vector<std::string>& domains) const {
    // 1. 端口匹配（port 0 表示全端口）
    // 使用 vector 替代 unordered_set，对于小数据集性能更好
    std::vector<flow::RuleId> port_matches;
    auto port_results = port_matcher_.match(dstPort);
    auto zero_port_results = port_matcher_.match(0);

    // 预分配空间
    port_matches.reserve(port_results.size() + zero_port_results.size());
    port_matches.insert(port_matches.end(), port_results.begin(), port_results.end());
    port_matches.insert(port_matches.end(), zero_port_results.begin(), zero_port_results.end());

    // 排序并去重
    std::sort(port_matches.begin(), port_matches.end());
    port_matches.erase(std::unique(port_matches.begin(), port_matches.end()), port_matches.end());

    std::vector<flow::RuleId> final_matches;
    final_matches.reserve(16); // 预分配合理大小

    // 2. 判断是否使用 IP 匹配或域名匹配
    if (dstIP.isNil()) {
        // IP 为空：只使用域名匹配
        std::vector<flow::RuleId> domain_matches;
        for (const auto& domain : domains) {
            auto matches = domain_matcher_.match(domain);
            domain_matches.insert(domain_matches.end(), matches.begin(), matches.end());
        }

        // 排序并去重
        std::sort(domain_matches.begin(), domain_matches.end());
        domain_matches.erase(std::unique(domain_matches.begin(), domain_matches.end()), domain_matches.end());

        // 域名匹配与端口匹配取交集（使用 std::set_intersection）
        std::set_intersection(domain_matches.begin(), domain_matches.end(),
                            port_matches.begin(), port_matches.end(),
                            std::back_inserter(final_matches));
    } else {
        // IP 不为空：使用 IP 匹配，也可以结合域名匹配
        std::vector<flow::RuleId> ip_or_domain;
        auto ip_results = ip_index_.queryIds(dstIP);
        ip_or_domain.reserve(ip_results.size() + domains.size() * 4);
        ip_or_domain.insert(ip_or_domain.end(), ip_results.begin(), ip_results.end());

        // 域名匹配
        for (const auto& domain : domains) {
            auto matches = domain_matcher_.match(domain);
            ip_or_domain.insert(ip_or_domain.end(), matches.begin(), matches.end());
        }

        // 排序并去重
        std::sort(ip_or_domain.begin(), ip_or_domain.end());
        ip_or_domain.erase(std::unique(ip_or_domain.begin(), ip_or_domain.end()), ip_or_domain.end());

        // 与端口匹配交集
        std::set_intersection(ip_or_domain.begin(), ip_or_domain.end(),
                            port_matches.begin(), port_matches.end(),
                            std::back_inserter(final_matches));
    }

    // 转换回 unordered_set（保持接口兼容）
    return std::unordered_set<flow::RuleId>(final_matches.begin(), final_matches.end());
}


bool PolicyEngine::parseAddress(const std::string& address,
                              flow::FlowIP& ip,
                              flow::IPv4CIDR& v4_cidr,
                              flow::IPv4Range& v4_range,
                              flow::IPv6CIDR& v6_cidr,
                              flow::IPv6Range& v6_range) const {
    if (address.empty()) {
        return false;
    }

    // 尝试解析为 CIDR
    if (address.find('/') != std::string::npos) {
        if (address.find(':') != std::string::npos) {
            auto cidr = flow::IPUtils::parseIPv6CIDR(address.c_str());
            if (cidr) {
                v6_cidr = *cidr;
                return true;
            }
        } else {
            auto cidr = flow::IPUtils::parseIPv4CIDR(address.c_str());
            if (cidr) {
                v4_cidr = *cidr;
                return true;
            }
        }
        return false;  // CIDR format but parsing failed
    }
    // 尝试解析为范围
    else if (address.find('-') != std::string::npos) {
        if (address.find(':') != std::string::npos) {
            auto range = flow::IPUtils::parseIPv6Range(address.c_str());
            if (range) {
                v6_range = *range;
                return true;
            }
        } else {
            auto range = flow::IPUtils::parseIPv4Range(address.c_str());
            if (range) {
                v4_range = *range;
                return true;
            }
        }
        return false;  // Range format but parsing failed
    }
    // 尝试解析为精确 IP
    else if (address.find(':') != std::string::npos) {
        uint64_t hi, lo;
        if (flow::IPUtils::parseIPv6(address.c_str(), hi, lo)) {
            ip = flow::FlowIP::fromIPv6(hi, lo);
            return true;
        }
        // IPv6 parsing failed, might be a domain, continue
    }

    // 尝试解析为 IPv4
    if (address.find('.') != std::string::npos) {
        uint32_t ip_val;
        if (flow::IPUtils::parseIPv4(address.c_str(), ip_val)) {
            ip = flow::FlowIP::fromIPv4(ip_val);
            return true;
        }
        // IPv4 parsing failed, might be a domain, continue
    }

    // 域名（包含 '*' 或 '.'）
    if (address[0] == '*' || address.find('.') != std::string::npos) {
        return true;
    }

    return false;
}

bool PolicyEngine::parsePortString(const std::string& portStr, const flow::RuleId ruleId, std::vector<flow::PortMatcher::Rule>& rules) {
    std::stringstream ss(portStr);
    std::string token;

    if (portStr.empty())
    {
        rules.push_back({static_cast<uint16_t>(0),
                             static_cast<uint16_t>(0),
                             ruleId});
        return true;
    }
    

    // 支持逗号分隔
    while (std::getline(ss, token, ',')) {
        token = trim(token);
        if (token.empty()) continue;

        size_t dashPos = token.find('-');
        if (dashPos != std::string::npos) {
            // 端口范围
            int begin = std::stoi(token.substr(0, dashPos));
            int end   = std::stoi(token.substr(dashPos + 1));
            if (begin < 0 || end < 0 || begin > 65535 || end > 65535 || begin > end) {
                return false;
            }
            rules.push_back({static_cast<uint16_t>(begin),
                             static_cast<uint16_t>(end),
                             ruleId});
        } else {
            // 单个端口
            int p = std::stoi(token);
            if (p < 0 || p > 65535) {
                return false;
            }
            rules.push_back({static_cast<uint16_t>(p),
                             static_cast<uint16_t>(p),
                             ruleId});
        }
    }

    return true;
}


} // namespace policy
