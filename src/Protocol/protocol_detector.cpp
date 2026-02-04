#include "protocol_detector.hpp"
#include <cstring>
#include <cctype>

namespace proto {

Detector::Detector(uint32_t cache_ttl, size_t cache_size)
    : m_cache(std::make_unique<flow::FlowCache>(cache_ttl, cache_size)) {
}

ProtocolType Detector::detectProtocol(const flow::PacketView& pkt,
                                        const flow::FlowContext& ctx) {
    // ===== 第一层：流缓存（最快，~0.1μs）=====
    flow::FlowKey key = buildFlowKey(ctx);
    ProtocolType cached = m_cache->lookup(key);
    if (cached != ProtocolType::Unknown) {
        return cached;
    }

    // ===== 第二层：端口提示 + 快速验证（~0.5μs）=====
    ProtocolType hint = getPortBasedHint(ctx);
    if (hint != ProtocolType::Unknown) {
        // 不直接返回，而是快速验证
        if (quickVerify(pkt, hint)) {
            m_cache->update(key, hint);
            return hint;
        }
        // 端口提示失败，继续全协议检测
    }

    // ===== 第三层：特征优先级检测（~2-3μs）=====
    ProtocolType detected = detectBySignature(pkt);

    // 更新缓存
    if (detected != ProtocolType::Unknown) {
        m_cache->update(key, detected);
    }

    return detected;
}

flow::FlowKey Detector::buildFlowKey(const flow::FlowContext& ctx) const {
    flow::FlowKey key;
    key.src_ip = ctx.tuple.src_ip;
    key.dst_ip = ctx.tuple.dst_ip;
    key.src_port = ctx.tuple.src_port;
    key.dst_port = ctx.tuple.dst_port;
    key.protocol = (ctx.tuple.proto == flow::L4Proto::TCP) ? 6 : 17;
    return key;
}

ProtocolType Detector::getPortBasedHint(const flow::FlowContext& ctx) const {
    // 端口仅作为"提示"，不作为唯一依据
    // 每个协议负责维护自己的标准端口
    uint16_t port = ctx.tuple.dst_port;

    if (ctx.tuple.proto == flow::L4Proto::TCP) {
        // 按流量占比排序（高频协议优先检测）
        if (TLS::matchesStandardPort(port)) return ProtocolType::HTTPS;
        if (HTTP::matchesStandardPort(port)) return ProtocolType::HTTP;
        if (SSH::matchesStandardPort(port)) return ProtocolType::SSH;
        if (FTP::matchesStandardPort(port)) return ProtocolType::FTP;
        if (SMTP::matchesStandardPort(port)) return ProtocolType::SMTP;
        if (IMAP::matchesStandardPort(port)) return ProtocolType::IMAP;
        if (POP3::matchesStandardPort(port)) return ProtocolType::POP3;
        if (SMB::matchesStandardPort(port)) return ProtocolType::SMB;
    } else if (ctx.tuple.proto == flow::L4Proto::UDP) {
        // DNS: TCP/UDP 53，TCP 用于大响应，需要 2 字节长度前缀
        if (dns::DNSParser::matchesStandardPort(port)) return ProtocolType::DNS;
        if (QUIC::matchesStandardPort(port)) return ProtocolType::QUIC;
        if (TFTP::matchesStandardPort(port)) return ProtocolType::TFTP;
    }

    return ProtocolType::Unknown;
}

bool Detector::quickVerify(const flow::PacketView& pkt, ProtocolType hint) {
    // 快速验证端口提示是否正确
    switch (hint) {
        case ProtocolType::HTTP:
            return m_http_parser.isRequest(pkt.data, pkt.length);

        case ProtocolType::HTTPS:
            return m_tls_parser.isRecord(pkt.data, pkt.length);

        case ProtocolType::SSH:
            return m_ssh_parser.isMessage(pkt.data, pkt.length);

        case ProtocolType::FTP:
            return m_ftp_parser.isMessage(pkt.data, pkt.length);

        case ProtocolType::SMTP:
            return m_smtp_parser.isMessage(pkt.data, pkt.length);

        case ProtocolType::IMAP:
            return m_imap_parser.isMessage(pkt.data, pkt.length);

        case ProtocolType::POP3:
            return m_pop3_parser.isMessage(pkt.data, pkt.length);

        case ProtocolType::SMB:
            return m_smb_parser.isMessage(pkt.data, pkt.length);

        case ProtocolType::TFTP:
            return m_tftp_parser.isMessage(pkt.data, pkt.length);

        case ProtocolType::QUIC:
            return m_quic_parser.isPacket(pkt.data, pkt.length);

        case ProtocolType::DNS:
            return m_dns_parser.parse(pkt.data, pkt.length, m_tmp_dns_msg);

        default:
            return false;
    }
}

ProtocolType Detector::detectBySignature(const flow::PacketView& pkt) {
    // 基于特征的完整检测（按流量占比优化顺序）
    // 统计显示：TLS/HTTP/DNS 占 95%+ 的互联网流量

    // 1. DNS (UDP 或 TCP) - 占 UDP 流量 ~60-70%
    if (m_dns_parser.parse(pkt.data, pkt.length, m_tmp_dns_msg)) {
        return ProtocolType::DNS;
    }

    // 2. 仅 TCP 流量检测应用层协议
    if (pkt.proto == flow::L4Proto::TCP) {
        // 2a. TLS/HTTPS - 占 TCP 流量 ~70%
        if (m_tls_parser.isRecord(pkt.data, pkt.length)) {
            if (m_tls_parser.isClientHello(pkt.data, pkt.length)) {
                return ProtocolType::HTTPS;
            }
            return ProtocolType::TLS;
        }

        // 2b. HTTP - 占 TCP 流量 ~20%
        if (m_http_parser.isRequest(pkt.data, pkt.length)) {
            return ProtocolType::HTTP;
        }

        // 2c. SSH - 占 TCP 流量 ~2-3%
        if (m_ssh_parser.isMessage(pkt.data, pkt.length)) {
            // 子协议检测
            if (m_ssh_parser.isSFTPPacket(pkt.data, pkt.length)) {
                return ProtocolType::SFTP;
            }
            if (m_ssh_parser.isSCPPacket(pkt.data, pkt.length)) {
                return ProtocolType::SCP;
            }
            return ProtocolType::SSH;
        }

        // 2d. 其他低频协议（合计占比 < 5%）
        if (m_ftp_parser.isMessage(pkt.data, pkt.length)) {
            return ProtocolType::FTP;
        }

        if (m_smtp_parser.isMessage(pkt.data, pkt.length)) {
            return ProtocolType::SMTP;
        }

        if (m_imap_parser.isMessage(pkt.data, pkt.length)) {
            return ProtocolType::IMAP;
        }

        if (m_pop3_parser.isMessage(pkt.data, pkt.length)) {
            return ProtocolType::POP3;
        }

        if (m_smb_parser.isMessage(pkt.data, pkt.length)) {
            return ProtocolType::SMB;
        }
    }

    // 3. 仅 UDP 流量
    if (pkt.proto == flow::L4Proto::UDP) {
        // 3a. QUIC - 占 UDP 流量 ~15-20%（逐渐增加）
        if (m_quic_parser.isPacket(pkt.data, pkt.length)) {
            return ProtocolType::QUIC;
        }

        // 3b. TFTP
        if (m_tftp_parser.isMessage(pkt.data, pkt.length)) {
            return ProtocolType::TFTP;
        }

        // 3c. RTP/RTCP
        if (m_rtp_parser.isRTPPacket(pkt.data, pkt.length)) {
            return ProtocolType::RTP;
        }
        if (m_rtp_parser.isRTCPPacket(pkt.data, pkt.length)) {
            return ProtocolType::RTCP;
        }
    }

    // 4. 无法识别的应用层协议
    if (pkt.proto == flow::L4Proto::TCP) {
        return ProtocolType::TCP;
    } else {
        return ProtocolType::UDP;
    }
}

std::optional<std::string> Detector::extractDomain(
    const flow::PacketView& pkt,
    const flow::FlowContext& ctx,
    ProtocolType protocol
) {
    // 如果未指定协议类型，自动检测
    if (protocol == ProtocolType::Unknown) {
        protocol = detectProtocol(pkt, ctx);
    }

    // 根据协议类型调用对应的解析器
    if (protocol == ProtocolType::DNS) {
        return extractDNSDomain(pkt.data, pkt.length);
    } else if (protocol == ProtocolType::HTTP) {
        return extractHTTPHost(pkt.data, pkt.length);
    } else if (protocol == ProtocolType::HTTPS) {
        return extractTLSSNI(pkt.data, pkt.length);
    }
    // TODO: 实现其他协议的域名提取

    return std::nullopt;
}

void Detector::clearCache() {
    m_cache->clear();
}

flow::FlowCache::Stats Detector::getCacheStats() const {
    return m_cache->get_stats();
}

// ========== 域名提取 ==========

std::optional<std::string> Detector::extractDNSDomain(
    const uint8_t* data, size_t length
) {
    if (!m_dns_parser.parse(data, length, m_tmp_dns_msg)) {
        return std::nullopt;
    }

    if (m_tmp_dns_msg.questions.empty()) {
        return std::nullopt;
    }

    return m_tmp_dns_msg.questions[0].name;
}

std::optional<std::string> Detector::extractHTTPHost(
    const uint8_t* data, size_t length
) {
    auto result = m_http_parser.parseHost(data, length);

    if (result.success) {
        return result.host;
    }
    return std::nullopt;
}

std::optional<std::string> Detector::extractTLSSNI(
    const uint8_t* data, size_t length
) {
    auto result = m_tls_parser.parseSNI(data, length);

    if (result.success) {
        return result.sni;
    }
    return std::nullopt;
}

} // namespace proto
