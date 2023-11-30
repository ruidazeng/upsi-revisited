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
#include <utility>

#include "absl/flags/flag.h"
#include "absl/flags/parse.h"
#include "absl/strings/str_cat.h"
#include "include/grpc/grpc_security_constants.h"
#include "include/grpcpp/channel.h"
#include "include/grpcpp/client_context.h"
#include "include/grpcpp/create_channel.h"
#include "include/grpcpp/grpcpp.h"
#include "include/grpcpp/security/credentials.h"
#include "include/grpcpp/support/status.h"
#include "upsi/party_zero_impl.h"
#include "upsi/data_util.h"
#include "upsi/upsi.grpc.pb.h"
#include "upsi/upsi.pb.h"
#include "upsi/protocol_client.h"
#include "upsi/util/status.inc"

ABSL_FLAG(std::string, port,    "0.0.0.0:10501",  "port to connect to server");
ABSL_FLAG(std::string, dataset, "party_zero.csv", "filename for the dataset");
ABSL_FLAG(std::string, sk_fn,   "party_zero.key", "filename for elgamal secret key");
ABSL_FLAG(std::string, pk_fn,   "shared.pub",     "filename for shared elgamal public key");

ABSL_FLAG(
    int32_t,
    paillier_modulus_size,
    1536,
    "The bit-length of the modulus to use for Paillier encryption. The modulus "
    "will be the product of two safe primes, each of size paillier_modulus_size/2."
);

ABSL_FLAG(int32_t, paillier_statistical_param, 100, "Paillier statistical parameter.");

ABSL_FLAG(int, total_days, 5, "Number of days the protocol will run.");

namespace upsi {
namespace {

class InvokeServerHandleClientMessageSink : public MessageSink<ClientMessage> {
    public:
        explicit InvokeServerHandleClientMessageSink(std::unique_ptr<UPSIRpc::Stub> stub)
            : stub_(std::move(stub)) {}

        ~InvokeServerHandleClientMessageSink() override = default;

        Status Send(const ClientMessage& message) override {
            ::grpc::ClientContext client_context;
            ::grpc::Status grpc_status =
                stub_->Handle(&client_context, message, &last_server_response_);
            if (grpc_status.ok()) {
                return OkStatus();
            } else {
                return InternalError(absl::StrCat(
                            "GrpcClientMessageSink: Failed to send message, error code: ",
                            grpc_status.error_code(),
                            ", error_message: ", grpc_status.error_message()));
            }
        }

        const ServerMessage& last_server_response() { return last_server_response_; }

    private:
        std::unique_ptr<UPSIRpc::Stub> stub_;
        ServerMessage last_server_response_;
};

int RunPartyZero() {
    Context context;

    // read in dataset
    std::cout << "[PartyZero] loading data" << std::endl;
    auto maybe_dataset = ::upsi::ReadClientDatasetFromFile(
        absl::GetFlag(FLAGS_dataset),
        &context
    );
    if (!maybe_dataset.ok()) {
        std::cerr << "Party 0::RunPartyZero: failed " << maybe_dataset.status() << std::endl;
        return 1;
    }
    auto dataset = std::move(maybe_dataset.value());

    // TODO: Double check dummy data generation
    std::unique_ptr<::upsi::PartyZeroImpl> party_zero = std::make_unique<::upsi::PartyZeroImpl>(
        &context,
        absl::GetFlag(FLAGS_pk_fn),
        absl::GetFlag(FLAGS_sk_fn),
        std::move(dataset.first),
        std::move(dataset.second),
        absl::GetFlag(FLAGS_paillier_modulus_size),
        absl::GetFlag(FLAGS_paillier_statistical_param),
        absl::GetFlag(FLAGS_total_days)
    );

    // setup connection with other party
    std::unique_ptr<UPSIRpc::Stub> stub = UPSIRpc::NewStub(::grpc::CreateChannel(
        absl::GetFlag(FLAGS_port),
        ::grpc::experimental::LocalCredentials(
            grpc_local_connect_type::LOCAL_TCP
        )
    ));
    InvokeServerHandleClientMessageSink sink(std::move(stub));

    // execute ClientPreprocessing (Updatable)
    for (int i = 0; i <= absl::GetFlag(FLAGS_total_days); ++i) {
        // If not Day 0, load a new day of data
        if (i != 0) {
            std::cout << "Party 0: Loading data..." << std::endl;
            auto maybe_dataset = ::upsi::ReadClientDatasetFromFile(
                    absl::GetFlag(FLAGS_dataset),
                    &context
                    );
            if (!maybe_dataset.ok()) {
                std::cerr << "Party 0::RunPartyZero: failed "
                    << maybe_dataset.status()
                    << std::endl;
                return 1;
            }
            auto dataset = std::move(maybe_dataset.value());
            // CALL UPDATE ELEMENT AND PAYLOAD
            party_zero->UpdateElements(dataset.first);
            party_zero->UpdatePayloads(dataset.second);
        }
        // Round One Starting
        std::cout << "Party 0: Sending tree updates to Party 1."
            << std::endl;
        auto client_round_one_status =
            party_zero->ClientSendRoundOne(&sink);
            
        
        std::cout << "Party 0: Waiting for Party 1's tree updates..." << std::endl;
        if (!client_round_one_status.ok()) {
            std::cerr << "Party 0::RunPartyZero: failed to Client Proprocessing: "
                << client_round_one_status << std::endl;
            return 1;
        }

        ServerMessage server_round_one =
            sink.last_server_response();

        // Receiver ServerRoundOne, execute ClientPostProcessing.
        std::cout
            << "Party 0: Received tree updates from the Party 1, now doing postprocessing..."
            << std::endl;
        auto client_post_processing_status =
            party_zero->Handle(server_round_one, &sink);
        if (!client_post_processing_status.ok()) {
            std::cerr << "Party 0::RunPartyZero: failed to ReEncryptSet: "
                << client_post_processing_status << std::endl;
            return 1;
        }
    }

    return 0;
}

}  // namespace
}  // namespace upsi

int main(int argc, char** argv) {
    absl::ParseCommandLine(argc, argv);

    return upsi::RunPartyZero();
}
