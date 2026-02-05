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

    // 查询 DNS response cache，如果命中则返回缓存的响应
    std::vector<uint8_t> cachedResponse;
    if (mDnsRespCache.buildResponseFromCache(pkt.data, pkt.length, cachedResponse)) {
        // 缓存命中，返回注入响应
        ResolverResult result;
        result.action = ResolverAction::InjectResponse;
        result.responseData = std::move(cachedResponse);
        ctx.lastResolveAction = ResolverAction::InjectResponse;
        return result;
    }

    // DNS 查询直接 bypass（让真实 DNS 服务器处理）
    ResolverResult result;
    result.action = ResolverAction::Bypass;
    ctx.lastResolveAction = ResolverAction::Bypass;
    return result;
}

ResolverResult FlowResolver::handleDNSResponse(PacketView pkt, FlowContext& ctx) {
    // 基本长度校验
    if (pkt.length < 12) {
        // 非法 DNS 响应，直接 bypass
        ResolverResult result;
        result.action = ResolverAction::Bypass;
        return result;
    }

    // 解析 DNS 响应
    dns::DNSParser parser;
    dns::DNSMessage msg;
    if (!parser.parse(pkt.data, pkt.length, msg)) {
        // 解析失败，直接 bypass
        ResolverResult result;
        result.action = ResolverAction::Bypass;
        return result;
    }

    // 检查响应码
    if (msg.header.dns_rcode() != 0) {
        // DNS 错误响应（如 NXDOMAIN），直接 bypass
        ResolverResult result;
        result.action = ResolverAction::Bypass;
        return result;
    }

    // 提取 IP 地址和域名（CNAME）
    std::vector<std::string> ipList;
    std::vector<std::string> domainList;
    uint32_t maxTTL = 0;

    for (const auto& rr : msg.answers) {
        // 记录最大 TTL
        if (rr.ttl > maxTTL) {
            maxTTL = rr.ttl;
        }

        // 提取 IPv4 地址
        if (auto ip4 = rr.ipv4()) {
            ipList.push_back(*ip4);
            continue;
        }

        // 提取 IPv6 地址
        if (auto ip6 = rr.ipv6()) {
            ipList.push_back(*ip6);
            continue;
        }

        // 提取 CNAME 域名
        if (rr.domain) {
            domainList.push_back(*rr.domain);
            ctx.domains.push_back(*rr.domain);
        }
    }

    // 如果提取到 IP 地址或域名，存储到缓存
    if (!ipList.empty() || !domainList.empty()) {
        // 存储完整的 DNS 响应到缓存
        mDnsRespCache.storeResponse(pkt.data, pkt.length);

        // 将 IP-Domain 映射存储到专门的索引中
        // 用于反向查询（根据 IP 查找域名）
        if (!ipList.empty() && !ctx.domains.empty()) {
            // 合并查询域名和 CNAME 域名
            std::vector<std::string> allDomains = ctx.domains;
            allDomains.insert(allDomains.end(), domainList.begin(), domainList.end());

            // 为每个 IP 地址建立域名映射
            for (const auto& ipStr : ipList) {
                FlowIP flowIP = FlowContext::parseIPString(ipStr);
                if (!flowIP.isNil()) {
                    mIPDomainCache.addMapping(flowIP, allDomains, maxTTL);
                }
            }
        }
    }

    // DNS 响应直接 bypass
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
        ctx.tuple.dst_ip,
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
        ctx.tuple.dst_ip,
        ctx.tuple.dst_port,
        ctx.domains
    );

    // 6. 暂时全部返回 bypass（策略匹配未完全实现）
    ResolverResult result;
    result.action = ResolverAction::Bypass;
    ctx.lastResolveAction = ResolverAction::Bypass;
    return result;
}

std::vector<std::string> FlowResolver::queryDomainsByIP(const FlowIP& ip) {
    return mIPDomainCache.queryDomains(ip);
}

void FlowResolver::cleanExpiredIPDomainCache() {
    mIPDomainCache.cleanExpired();
}
