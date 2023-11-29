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

#include <iostream>
#include <memory>
#include <ostream>
#include <string>
#include <thread>  // NOLINT
#include <utility>

#include "absl/flags/flag.h"
#include "absl/flags/parse.h"
#include "include/grpc/grpc_security_constants.h"
#include "include/grpcpp/grpcpp.h"
#include "include/grpcpp/security/server_credentials.h"
#include "include/grpcpp/server_builder.h"
#include "include/grpcpp/server_context.h"
#include "include/grpcpp/support/status.h"
#include "updatable_private_set_intersection/data_util.h"
#include "updatable_private_set_intersection/updatable_private_set_intersection.grpc.pb.h"
#include "updatable_private_set_intersection/updatable_private_set_intersection_rpc_impl.h"
#include "updatable_private_set_intersection/protocol_server.h"
#include "updatable_private_set_intersection/party_one_impl.h"

ABSL_FLAG(std::string, port, "0.0.0.0:10501", "Port on which to listen");
ABSL_FLAG(std::string, server_data_file, "",
          "The file from which to read the server database.");
ABSL_FLAG(
    int32_t, paillier_modulus_size, 1536,
    "The bit-length of the modulus to use for Paillier encryption. The modulus "
    "will be the product of two safe primes, each of size "
    "paillier_modulus_size/2.");
ABSL_FLAG(
    int32_t, paillier_statistical_param, 100,
    "Paillier statistical parameter.");
ABSL_FLAG(
    int, total_days, 5, 
    "Number of days the protocol will run.");


int RunPartyOne() {
  std::cout << "Party 1: loading data... " << std::endl;
  // Note that the server does not handle payload, even in secret shares.
  auto maybe_server_identifiers =
        ::updatable_private_set_intersection::ReadServerDatasetFromFile(
            absl::GetFlag(FLAGS_server_data_file));
    if (!maybe_server_identifiers.ok()) {
      std::cerr << "RunServer: failed " << maybe_server_identifiers.status()
                << std::endl;
      return 1;
    }

  ::updatable_private_set_intersection::Context context;
  std::unique_ptr<::updatable_private_set_intersection::ProtocolServer> party_one =
      std::make_unique<
          ::updatable_private_set_intersection::PrivateIntersectionProtocolPartyOneImpl>(
          &context, std::move(maybe_server_identifiers.value()),
          absl::GetFlag(FLAGS_paillier_modulus_size),
          absl::GetFlag(FLAGS_paillier_statistical_param),
          absl::GetFlag(FLAGS_total_days));

  ::updatable_private_set_intersection::UpdatablePrivateSetIntersectionRpcImpl service(
      std::move(party_one));

  ::grpc::ServerBuilder builder;
  // Consider grpc::SslServerCredentials if not running locally.
  builder.AddListeningPort(absl::GetFlag(FLAGS_port),
                           ::grpc::experimental::LocalServerCredentials(
                               grpc_local_connect_type::LOCAL_TCP));
  builder.RegisterService(&service);
  std::unique_ptr<::grpc::Server> grpc_server(builder.BuildAndStart());

  // BIG TODO - SERVER NOT UPDATING ELEMENTS AND PAYLOADS???
  // Run the server on a background thread.
  std::thread grpc_server_thread(
      [](::grpc::Server* grpc_server_ptr) {
        std::cout << "Party 1: listening on " << absl::GetFlag(FLAGS_port)
                  << std::endl;
        grpc_server_ptr->Wait();
      },
      grpc_server.get());

  while (!service.protocol_finished()) {
    // Wait for the server to be done, and then shut the server down.
  }

  // Shut down server.
  grpc_server->Shutdown();
  grpc_server_thread.join();
  std::cout << "Party 1 completed protocol and shut down." << std::endl;

  return 0;
}

int main(int argc, char** argv) {
  absl::ParseCommandLine(argc, argv);

  return RunPartyOne();
}
