#ifndef policy_engine_hpp
#define policy_engine_hpp

#include <string>
#include <vector>
#include <cstdint>
#include <optional>
#include <algorithm>
#include <unordered_map>
#include <unordered_set>
#include "../Filter/filter_common.h"
#include "../Filter/ip_index.h"
#include "../Filter/domain_matcher.h"
#include "../Filter/port_matcher.h"

namespace proto {
    enum class ProtocolType : int;
}

namespace policy {
struct Policy {
    flow::RuleId rule_id;
    std::string address;       // ipv4, ipv6, ipcidr, iprange, domain, wildcard domain
    std::string port; // single port, multiple ports, port-range
};

class PolicyEngine {
public:
    PolicyEngine();
    ~PolicyEngine() = default;

    bool addPolicy(const Policy& policy);
    bool removePolicy(flow::RuleId rule_id);
    void clear();
    size_t getPolicyCount() const;

    std::unordered_set<flow::RuleId> match(
        proto::ProtocolType protocol,
        const flow::FlowIP& dstIP,
        uint16_t dstPort,
        const std::vector<std::string>& domains
    ) const;

private:
    bool parseAddress(const std::string& address,
                     flow::FlowIP& ip,
                     flow::IPv4CIDR& v4_cidr,
                     flow::IPv4Range& v4_range,
                     flow::IPv6CIDR& v6_cidr,
                     flow::IPv6Range& v6_range) const;

    bool parsePortString(const std::string& portStr, 
                        const flow::RuleId ruleId, 
                        std::vector<flow::PortMatcher::Rule>& rules);

    void rebuildPortMatcher();

private:
    flow::IPIndex ip_index_;
    flow::PortMatcher port_matcher_;
    flow::DomainMatcher domain_matcher_;

    std::unordered_map<flow::RuleId, Policy> policies_;
    std::vector<flow::PortMatcher::Rule> port_rules_;
};

} // namespace policy

#endif // policy_engine_hpp
