#ifndef FlowResolver_hpp
#define FlowResolver_hpp

#include <vector>
#include <unordered_map>
#include <memory>
#include <functional>
#include "../DNS/dns_cache.hpp"
#include "ip_addr.hpp"

// 前向声明
namespace proto {
    enum class ProtocolType : int;
    class Detector;
}

namespace policy {
    class PolicyEngine;
}

namespace flow {

    enum class L4Proto {
        TCP,
        UDP
    };

    enum class Direction {
        Send,
        Recv
    };

    struct PacketView {
        const uint8_t* data;
        size_t length;

        L4Proto proto;
        Direction direction;
    };

    enum class ResolverAction {
        None,           // 未设置
        Bypass,         // 透明转发
        Forward,        // 转发Gateway
        Block,          // 丢弃并关闭
        InjectResponse  // 本地构造 response
    };

    struct ResolverResult {
        ResolverAction action;

        // 仅在 InjectResponse 时使用
        std::vector<uint8_t> responseData;
    };

    enum class DomainResolutionState {
        RequiresResolution,  // 需要解析
        Resolved,            // 已解析
        NotApplicable        // 不适用（无域名）
    };

    struct FlowContext {
        // 五元组（唯一标识一个流）
        struct FiveTuple {
            IpAddr src_ip;
            IpAddr dst_ip;
            uint16_t src_port;
            uint16_t dst_port;
            L4Proto proto;

            bool operator==(const FiveTuple& other) const {
                return src_ip == other.src_ip &&
                       dst_ip == other.dst_ip &&
                       src_port == other.src_port &&
                       dst_port == other.dst_port &&
                       proto == other.proto;
            }
        };

        // 流的唯一标识
        FiveTuple tuple;

        // 方向（从客户端到服务端，或反向）
        Direction direction;
        
        // 域名解析状态
        DomainResolutionState domainState;

        // lastResolveAction
        ResolverAction lastResolveAction;

        // 协议类型
        proto::ProtocolType protocol;

        // 提取的域名列表（可能有多个，如DNS CNAME链）
        std::vector<std::string> domains;

    };

    /**
     * 解析域名，并进行规则匹配
     *
     */
    class FlowResolver {
    public:
        FlowResolver();
        ~FlowResolver() = default;
        ResolverResult onSendData(PacketView pkt, FlowContext& ctx);
        ResolverResult onRecvData(PacketView pkt, FlowContext& ctx);

    private:
        ResolverResult handleDNSQuery(PacketView pkt, FlowContext& ctx);
        ResolverResult handleDNSResponse(PacketView pkt, FlowContext& ctx);

    private:
        std::unique_ptr<proto::Detector> mProtocolDetector;
        std::unique_ptr<policy::PolicyEngine> mPolicyEngine;
        dns::DNSResponseCache mDnsRespCache;

    };


}


// Hash 函数特化（用于 unordered_map）
namespace std {

    template<>
    struct hash<flow::FlowContext::FiveTuple> {
        size_t operator()(const flow::FlowContext::FiveTuple& ft) const {
            size_t h1 = hash<flow::IpAddr>{}(ft.src_ip);
            size_t h2 = hash<flow::IpAddr>{}(ft.dst_ip);
            size_t h3 = hash<uint16_t>{}(ft.src_port);
            size_t h4 = hash<uint16_t>{}(ft.dst_port);
            size_t h5 = hash<uint8_t>{}(static_cast<uint8_t>(ft.proto));

            // 组合哈希（boost::hash_combine 风格）
            size_t seed = h1;
            seed ^= h2 + 0x9e3779b9 + (seed << 6) + (seed >> 2);
            seed ^= h3 + 0x9e3779b9 + (seed << 6) + (seed >> 2);
            seed ^= h4 + 0x9e3779b9 + (seed << 6) + (seed >> 2);
            seed ^= h5 + 0x9e3779b9 + (seed << 6) + (seed >> 2);
            return seed;
        }
    };

}

#endif /* FlowResolver_hpp */
