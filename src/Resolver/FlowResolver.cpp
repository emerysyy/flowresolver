#include "FlowResolver.hpp"
#include "../DNS/dns_message.hpp"
#include "../Protocol/protocol_detector.hpp"
#include "../Policy/policy_engine.hpp"

using namespace flow;

FlowResolver::FlowResolver()
    : mProtocolDetector(new proto::Detector(60, 10000))
    , mPolicyEngine(new policy::PolicyEngine())
    , mDnsRespCache(1024)
{
}

ResolverResult FlowResolver::handleDNSQuery(PacketView pkt, FlowContext& ctx) {
    // 解析 DNS 查询，提取所有域名
    dns::DNSMessage dnsMsg;
    dns::DNSParser parser;

    if (parser.parse(pkt.data, pkt.length, dnsMsg)) {
        // 提取所有查询的域名
        for (const auto& question : dnsMsg.questions) {
            ctx.domains.push_back(question.name);
        }

        // 更新状态
        if (!ctx.domains.empty()) {
            ctx.domainState = DomainResolutionState::Resolved;
        } else {
            ctx.domainState = DomainResolutionState::NotApplicable;
        }
    } else {
        ctx.domainState = DomainResolutionState::NotApplicable;
    }

    // DNS 查询直接 bypass
    ResolverResult result;
    result.action = ResolverAction::Bypass;
    ctx.lastResolveAction = ResolverAction::Bypass;
    return result;
}

ResolverResult FlowResolver::handleDNSResponse(PacketView pkt, FlowContext& ctx) {

    //TODO: 解析DNS响应，提取IP 构建 IP-DOMAIN 缓存

    // 存储 DNS 响应到缓存
    mDnsRespCache.storeResponse(pkt.data, pkt.length);

    ResolverResult result;
    result.action = ResolverAction::Bypass;
    return result;
}

ResolverResult FlowResolver::onSendData(PacketView pkt, FlowContext& ctx) {
    // 1. 检测协议类型
    ctx.protocol = mProtocolDetector->detectProtocol(pkt, ctx);

    // 2. DNS 流量特殊处理
    if (ctx.protocol == proto::ProtocolType::DNS) {
        return handleDNSQuery(pkt, ctx);
    }

    // 3. 如果还需要解析域名，尝试提取
    if (ctx.domainState == DomainResolutionState::RequiresResolution) {
        auto domain = mProtocolDetector->extractDomain(pkt, ctx, ctx.protocol);

        if (domain.has_value() && !domain->empty()) {
            // 成功提取域名
            ctx.domains.push_back(*domain);
            ctx.domainState = DomainResolutionState::Resolved;
        }
        else {
            ctx.domainState = DomainResolutionState::NotApplicable;
        }
    }

    // 4. 如果上一次解析动作不为None，则直接返回上一次解析动作
    if (ctx.lastResolveAction != ResolverAction::None)
    {
        ResolverResult result;
        result.action = ctx.lastResolveAction;
        return result;
    }
    

    // 5. 匹配策略（protocol + IP + port + domains）
    auto matchResult = mPolicyEngine->match(
        ctx.protocol,
        ctx.tuple.src_ip,
        ctx.tuple.dst_ip,
        ctx.tuple.src_port,
        ctx.tuple.dst_port,
        ctx.domains
    );

    // 6. 暂时全部返回 bypass（策略匹配未完全实现）
    ResolverResult result;
    result.action = ResolverAction::Bypass;
    ctx.lastResolveAction = ResolverAction::Bypass;
    return result;
}

ResolverResult FlowResolver::onRecvData(PacketView pkt, FlowContext& ctx) {
    // 1. 检测协议类型
    ctx.protocol = mProtocolDetector->detectProtocol(pkt, ctx);

    // 2. DNS 响应特殊处理
    if (ctx.protocol == proto::ProtocolType::DNS) {
        return handleDNSResponse(pkt, ctx);
    }


    // 3. 匹配策略（protocol + IP + port + domains）
    auto matchResult = mPolicyEngine->match(
        ctx.protocol,
        ctx.tuple.src_ip,
        ctx.tuple.dst_ip,
        ctx.tuple.src_port,
        ctx.tuple.dst_port,
        ctx.domains
    );

    // 4. 暂时全部返回 bypass（策略匹配未完全实现）
    ResolverResult result;
    result.action = ResolverAction::Bypass;
    ctx.lastResolveAction = ResolverAction::Bypass;
    return result;
}
