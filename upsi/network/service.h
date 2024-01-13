#pragma once

#include <memory>
#include <utility>

#include "include/grpcpp/grpcpp.h"
#include "include/grpcpp/support/status.h"
#include "upsi/network/upsi.grpc.pb.h"
#include "upsi/network/upsi.pb.h"
#include "upsi/roles.h"

namespace upsi {

class UPSIService : public UPSIRpc::Service {
    public:
        std::shared_ptr<Server> server;

        explicit UPSIService(std::shared_ptr<Server> server) : server(std::move(server)) { }

        ::grpc::Status Handle(
            ::grpc::ServerContext* context,
            const ClientMessage* request,
            ServerMessage* response
        ) override;

        bool ProtocolFinished() {
            return server->ProtocolFinished();
        }
};

}  // namespace upsi
