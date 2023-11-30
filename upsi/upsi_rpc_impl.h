/*
 * Copyright 2019 Google LLC.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef upsi_upsi_RPC_IMPL_H_
#define upsi_upsi_RPC_IMPL_H_

#include <memory>
#include <utility>

#include "include/grpcpp/grpcpp.h"
#include "include/grpcpp/server_context.h"
#include "include/grpcpp/support/status.h"
#include "upsi/upsi.grpc.pb.h"
#include "upsi/upsi.pb.h"
#include "upsi/protocol_server.h"

namespace upsi {

// Implements the PrivateJoin and Compute RPC-handling Server.
class UPSIRpcImpl : public UPSIRpc::Service {
 public:
  // Takes as a parameter an implementation of the server actually implementing
  // the steps of the protocol.
  //
  // Important note: This class will internally create a server message sink
  // that accepts a SINGLE message in response to a Handle request, and fails
  // with INVALID_ARGUMENT if more than one message is supplied. All supplied
  // protocol_server_impls' Handle methods should therefore Send at most one
  // message to the server_message_sink.
  explicit UPSIRpcImpl(
      std::unique_ptr<ProtocolServer> protocol_server_impl)
      : protocol_server_impl_(std::move(protocol_server_impl)) {}

  // Executes a round of the protocol.
  ::grpc::Status Handle(::grpc::ServerContext* context,
                        const ClientMessage* request,
                        ServerMessage* response) override;

  bool protocol_finished() {
    return protocol_server_impl_->protocol_finished();
  }

 private:
  std::unique_ptr<ProtocolServer> protocol_server_impl_;
};

}  // namespace upsi

#endif  // upsi_upsi_RPC_IMPL_H_