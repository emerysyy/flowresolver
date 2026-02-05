#ifndef protocol_detector_hpp
#define protocol_detector_hpp

#include <string>
#include <cstdint>
#include <optional>
#include <memory>
#include "../Resolver/FlowResolver.hpp"
#include "../Resolver/flow_cache.hpp"
#include "tls_parser.hpp"
#include "http_parser.hpp"
#include "ssh_parser.hpp"
#include "ftp_parser.hpp"
#include "smtp_parser.hpp"
#include "imap_parser.hpp"
#include "pop3_parser.hpp"
#include "smb_parser.hpp"
#include "tftp_parser.hpp"
#include "quic_parser.hpp"
#include "rtp_parser.hpp"
#include "../DNS/dns_message.hpp"

namespace proto {

// 协议类型枚举
enum class ProtocolType {
    Unknown,    // 未知协议

    // 基础协议
    DNS,        // DNS (UDP/TCP)
    HTTP,       // HTTP/1.x
    HTTPS,      // HTTPS (TLS 上的 HTTP)
    TLS,        // TLS/SSL
    TCP,        // 纯 TCP
    UDP,        // 纯 UDP

    // 核心协议
    FTP,        // File Transfer Protocol
    SSH,        // Secure Shell
    SMTP,       // Simple Mail Transfer Protocol

    // 邮件协议
    IMAP,       // Internet Message Access Protocol
    POP3,       // Post Office Protocol v3

    // 文件传输协议
    SFTP,       // SSH File Transfer Protocol
    SCP,        // Secure Copy
    SMB,        // Server Message Block
    TFTP,       // Trivial File Transfer Protocol

    // 实时通信协议
    QUIC,       // QUIC (UDP-based)
    RTP,        // Real-time Transport Protocol
    RTCP,       // Real-time Transport Control Protocol
};

/**
 * Detector - 协议检测器（统一入口，优化版）
 *
 * 职责：
 * 1. detectProtocol() - 检测数据包的协议类型（带流缓存 + 端口提示）
 * 2. extractDomain() - 提取域名（内部调用各协议解析器）
 *
 * 优化策略：
 * - 第一层：流缓存（最快，~0.1μs）
 * - 第二层：端口提示 + 快速验证（~0.5μs）
 * - 第三层：特征优先级检测（~2-3μs）
 */
class Detector {
public:
    /**
     * 构造函数
     * @param cache_ttl 缓存过期时间（秒），默认 300 秒
     * @param cache_size 最大缓存条目数，默认 10000
     */
    Detector(uint32_t cache_ttl = 300, size_t cache_size = 10000);
    ~Detector() = default;

    /**
     * 检测数据包的协议类型（带流缓存 + 端口提示）
     */
    ProtocolType detectProtocol(const flow::PacketView& pkt,
                                const flow::FlowContext& ctx);

    /**
     * 提取域名 - 统一入口
     */
    std::optional<std::string> extractDomain(
        const flow::PacketView& pkt,
        const flow::FlowContext& ctx,
        ProtocolType protocol = ProtocolType::Unknown
    );

    /**
     * 清空流缓存
     */
    void clearCache();

    /**
     * 获取缓存统计信息
     */
    flow::FlowCache::Stats getCacheStats() const;

private:
    /**
     * 构建流键
     */
    flow::FlowKey buildFlowKey(const flow::FlowContext& ctx) const;

    /**
     * 端口提示（端口仅作为提示，不作为决定）
     */
    ProtocolType getPortBasedHint(const flow::FlowContext& ctx) const;

    /**
     * 快速验证端口提示
     */
    bool quickVerify(const flow::PacketView& pkt, ProtocolType hint);

    /**
     * 基于特征的完整检测（按流量占比优化顺序）
     */
    ProtocolType detectBySignature(const flow::PacketView& pkt);

    // DNS 域名提取（调用 DNS 解析器）
    std::optional<std::string> extractDNSDomain(const uint8_t* data, size_t length);
    std::optional<std::string> extractHTTPHost(const uint8_t* data, size_t length);
    std::optional<std::string> extractTLSSNI(const uint8_t* data, size_t length);

    // 流缓存
    std::unique_ptr<flow::FlowCache> m_cache;

    // Parser 实例复用（避免重复创建）
    TLS m_tls_parser;
    HTTP m_http_parser;
    SSH m_ssh_parser;
    FTP m_ftp_parser;
    SMTP m_smtp_parser;
    IMAP m_imap_parser;
    POP3 m_pop3_parser;
    SMB m_smb_parser;
    TFTP m_tftp_parser;
    QUIC m_quic_parser;
    RTP m_rtp_parser;
    dns::DNSParser m_dns_parser;
    dns::DNSMessage m_tmp_dns_msg; // 避免重复分配
};

} // namespace proto

#endif // protocol_detector_hpp
