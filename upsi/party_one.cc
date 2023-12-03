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

#include <chrono>
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
#include "upsi/data_util.h"
#include "upsi/upsi.grpc.pb.h"
#include "upsi/upsi_rpc_impl.h"
#include "upsi/protocol_server.h"
#include "upsi/party_one_impl.h"

using namespace upsi;

ABSL_FLAG(std::string, port,    "0.0.0.0:10501", "listening port");
ABSL_FLAG(std::string, sk_fn,   "party_one.key", "filename for elgamal secret key");
ABSL_FLAG(std::string, pk_fn,   "shared.pub",    "filename for shared elgamal public key");

ABSL_FLAG(std::string, dir, "data/", "name of directory for dataset files");
ABSL_FLAG(std::string, prefix, "party_one", "prefix for dataset files");

ABSL_FLAG(
    int32_t,
    paillier_modulus_size,
    1536,
    "The bit-length of the modulus to use for Paillier encryption. The modulus "
    "will be the product of two safe primes, each of size paillier_modulus_size/2."
);

ABSL_FLAG(int32_t, paillier_statistical_param, 100, "Paillier statistical parameter.");

ABSL_FLAG(int, days, 10, "total days the protocol will run for");


Status RunPartyOne() {
    Context context;

    // read in dataset
    std::clog << "[PartyOne] loading data... " << std::endl;
    ASSIGN_OR_RETURN(
        auto dataset,
        ReadPartyOneDataset(
            absl::GetFlag(FLAGS_dir),
            absl::GetFlag(FLAGS_prefix),
            absl::GetFlag(FLAGS_days)
        )
    );
    std::clog << "done." << std::endl;

    std::unique_ptr<ProtocolServer> party_one = std::make_unique<PartyOneImpl>(
        &context,
        absl::GetFlag(FLAGS_pk_fn),
        absl::GetFlag(FLAGS_sk_fn),
        std::move(dataset),
        absl::GetFlag(FLAGS_paillier_modulus_size),
        absl::GetFlag(FLAGS_paillier_statistical_param),
        absl::GetFlag(FLAGS_days)
    );

    // setup connection
    UPSIRpcImpl service(std::move(party_one));
    ::grpc::ServerBuilder builder;
    builder.SetMaxSendMessageSize(1024 * 1024 * 1024);
    builder.SetMaxMessageSize(1024 * 1024 * 1024);
    builder.SetMaxReceiveMessageSize(1024 * 1024 * 1024);
    builder.AddListeningPort(
        absl::GetFlag(FLAGS_port),
        ::grpc::experimental::LocalServerCredentials(
            grpc_local_connect_type::LOCAL_TCP
        )
    );
    builder.RegisterService(&service);
    std::unique_ptr<::grpc::Server> grpc_server(builder.BuildAndStart());

    // BIG TODO - SERVER NOT UPDATING ELEMENTS AND PAYLOADS???
    // Run the server on a background thread.
    std::thread grpc_server_thread([](::grpc::Server* grpc_server_ptr) {
        std::cout << "[PartyOne] listening on " << absl::GetFlag(FLAGS_port) << std::endl;
        grpc_server_ptr->Wait();
    }, grpc_server.get());

    while (!service.protocol_finished()) { }

    std::this_thread::sleep_for(std::chrono::seconds(1));
    // shut down server
    grpc_server->Shutdown();
    grpc_server_thread.join();
    std::cout << "[PartyOne] completed protocol and shut down" << std::endl;

    return OkStatus();
}

int main(int argc, char** argv) {
    absl::ParseCommandLine(argc, argv);

    if (!DEBUG) { std::clog.setstate(std::ios_base::failbit); }

    auto status = RunPartyOne();

    std::clog.clear();

    if (!status.ok()) {
        std::cerr << "[PartyOne] failure " << std::endl;
        std::cerr << status << std::endl;
        return 1;
    }

    return 0;
}
