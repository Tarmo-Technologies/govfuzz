// SPDX-License-Identifier: Apache-2.0
#include <string>
#include <vector>

namespace Gov {
class TelemetryService {
public:
    TelemetryService() = default;
    void Reset() { packets.clear(); }
    void Submit(const std::string& packet) { packets.push_back(packet); }
    std::size_t Count() const { return packets.size(); }

private:
    std::vector<std::string> packets;
};
}
