#pragma once

#include <memory>

#include "upsi/network/upsi.pb.h"
#include "upsi/util/status.inc"

namespace upsi {

// an interface for message sinks.
template<typename T>
class MessageSink {
    public:
        virtual ~MessageSink() = default;

        // subclasses should accept a message and process it appropriately.
        virtual Status Send(const T& message) = 0;

    protected:
        MessageSink() = default;
};
}  // namespace upsi
