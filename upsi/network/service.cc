#include "upsi/network/service.h"

#include <thread>

#include "upsi/util/status.inc"

namespace upsi {
namespace {

// Translates Status to grpc::Status
::grpc::Status ConvertStatus(const Status& status) {
    if (status.ok()) {
        return ::grpc::Status::OK;
    }
    if (IsInvalidArgument(status)) {
        return ::grpc::Status(::grpc::StatusCode::INVALID_ARGUMENT,
            std::string(status.message()));
    }
    if (IsInternal(status)) {
        return ::grpc::Status(::grpc::StatusCode::INTERNAL,
            std::string(status.message()));
    }
    return ::grpc::Status(::grpc::StatusCode::UNKNOWN,
        std::string(status.message()));
}

class ServerSink : public MessageSink<ServerMessage> {
    public:
        explicit ServerSink(ServerMessage* msg) : server_message_(msg) {}

        ~ServerSink() override = default;

        Status Send(const ServerMessage& server_message) override {
            if (!message_sent_) {
                *server_message_ = server_message;
                message_sent_ = true;
                return OkStatus();
            } else {
                return InvalidArgumentError(
                    "ServerSink can only accept a single message."
                );
            }
        }

    private:
        ServerMessage* server_message_ = nullptr;
        bool message_sent_ = false;
};

}  // namespace

::grpc::Status UPSIService::Handle(
    ::grpc::ServerContext* context,
    const ClientMessage* request,
    ServerMessage* response
) {
    ServerSink sink(response);
    auto status = server->Handle(*request, &sink);
    return ConvertStatus(status);
}

}  // namespace upsi
