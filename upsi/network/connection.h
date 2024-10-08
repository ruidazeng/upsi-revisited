#pragma once

#include <iostream>
#include <memory>
#include <ostream>
#include <string>
#include <utility>

#include "absl/strings/str_cat.h"
#include "include/grpc/grpc_security_constants.h"
#include "include/grpcpp/channel.h"
#include "include/grpcpp/client_context.h"
#include "include/grpcpp/create_channel.h"
#include "include/grpcpp/grpcpp.h"
#include "include/grpcpp/security/credentials.h"
#include "include/grpcpp/support/status.h"
#include "upsi/network/connection.h"
#include "upsi/network/message_sink.h"
#include "upsi/network/upsi.grpc.pb.h"
#include "upsi/network/upsi.pb.h"
#include "upsi/util/status.inc"

namespace upsi {

class Connection : public MessageSink<ClientMessage> {
    public:
        explicit Connection(
            std::unique_ptr<UPSIRpc::Stub> stub
        ) : stub_(std::move(stub)) { }

        ~Connection() override = default;

        Status Send(const ClientMessage& message) override {
            ::grpc::ClientContext client_context;
            client_context.set_deadline(std::chrono::system_clock::time_point::max());
            ::grpc::Status grpc_status = stub_->Handle(
                &client_context, message, &response_
            );

            if (grpc_status.ok()) {
                return OkStatus();
            } else {
                return InternalError(
                    absl::StrCat(
                        "[ClientMessageSink] failed to send message, error code: ",
                        grpc_status.error_code(),
                        ", error_message: \n", grpc_status.error_message()
                    )
                );
            }
        }

        const ServerMessage& GetResponse() { return response_; }

    private:
        std::unique_ptr<UPSIRpc::Stub> stub_;
        ServerMessage response_;
};

}
