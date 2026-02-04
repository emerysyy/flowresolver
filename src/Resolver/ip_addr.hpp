#ifndef ip_addr_hpp
#define ip_addr_hpp

#include <cstdint>
#include <cstring>
#include <functional>

namespace flow
{

    /**
     * IP 地址类型
     */
    enum class IpAddrType : uint8_t
    {
        IPv4,
        IPv6
    };

    /**
     * IP 地址结构（支持 IPv4 和 IPv6）
     */
    struct IpAddr
    {
        IpAddrType type;

        union
        {
            uint32_t v4;    // IPv4: 4 bytes
            uint8_t v6[16]; // IPv6: 16 bytes
        } addr;

        // 构造函数
        IpAddr() : type(IpAddrType::IPv4) { addr.v4 = 0; }

        static IpAddr fromV4(uint32_t ip)
        {
            IpAddr a;
            a.type = IpAddrType::IPv4;
            a.addr.v4 = ip;
            return a;
        }

        static IpAddr fromV6(const uint8_t *ip)
        {
            IpAddr a;
            a.type = IpAddrType::IPv6;
            std::memcpy(a.addr.v6, ip, 16);
            return a;
        }

        bool operator==(const IpAddr &other) const
        {
            if (type != other.type)
                return false;
            if (type == IpAddrType::IPv4)
                return addr.v4 == other.addr.v4;
            return std::memcmp(addr.v6, other.addr.v6, 16) == 0;
        }

        bool operator!=(const IpAddr &other) const
        {
            return !(*this == other);
        }
    };

} // namespace flow

// Hash 函数特化
namespace std
{

    template <>
    struct hash<flow::IpAddr>
    {
        size_t operator()(const flow::IpAddr &ip) const
        {
            size_t h = static_cast<size_t>(ip.type);

            if (ip.type == flow::IpAddrType::IPv4)
            {
                h ^= std::hash<uint32_t>{}(ip.addr.v4) + 0x9e3779b9 + (h << 6) + (h >> 2);
            }
            else
            {
                // 安全处理：避免未对齐访问
                for (int i = 0; i < 16; i += 4)
                {
                    uint32_t val;
                    std::memcpy(&val, &ip.addr.v6[i], 4);
                    h ^= val + 0x9e3779b9 + (h << 6) + (h >> 2);
                }
            }
            return h;
        }
    };

}

#endif // ip_addr_hpp
