#ifndef policy_engine_hpp
#define policy_engine_hpp

#include <string>
#include <vector>
#include <cstdint>
#include <optional>
#include <algorithm>
#include "../Filter/ip_index.h"

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
    std::optional<flow::FlowIP> redirectIP;  // 重定向目标IP
};

struct Policy {
    uint32_t ruleid;
    std::string address; /// 可能是ipv4 ipv6, ipcidr, iprange, domain, wildcard domain
    std::optional<uint16_t> port; /// 可能未设置domain
};


/**
 * 策略引擎
 * 只做规则匹配
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
        const flow::FlowIP& srcIP,
        const flow::FlowIP& dstIP,
        uint16_t srcPort,
        uint16_t dstPort,
        const std::vector<std::string>& domains
    ) const;

};

} // namespace policy

#endif // policy_engine_hpp
