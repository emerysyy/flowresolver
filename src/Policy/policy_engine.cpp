#include "policy_engine.hpp"
#include "../Protocol/protocol_detector.hpp"

namespace policy {

PolicyEngine::PolicyEngine() {

}

MatchResult PolicyEngine::match(proto::ProtocolType protocol,
                                const flow::FlowIP& srcIP,
                                const flow::FlowIP& dstIP,
                                uint16_t srcPort,
                                uint16_t dstPort,
                                const std::vector<std::string>& domains) const {
             
    MatchResult result;
    return result;
}

} // namespace policy
