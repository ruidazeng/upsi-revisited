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
ABSL_FLAG(std::string, sk_fn,   "party_zero.key", "filename for elgamal secret key");
ABSL_FLAG(std::string, pk_fn,   "shared.pub",     "filename for shared elgamal public key");

ABSL_FLAG(std::string, dir, "data/", "name of directory for dataset files");
ABSL_FLAG(std::string, prefix, "party_zero", "prefix for dataset files");

ABSL_FLAG(
    int32_t,
    paillier_modulus_size,
    1536,
    "The bit-length of the modulus to use for Paillier encryption. The modulus "
    "will be the product of two safe primes, each of size paillier_modulus_size/2."
);

ABSL_FLAG(int32_t, paillier_statistical_param, 100, "Paillier statistical parameter.");

ABSL_FLAG(int, days, 10, "total days the protocol will run for");

namespace upsi {
namespace {

class InvokeServerHandleClientMessageSink : public MessageSink<ClientMessage> {
    public:
        explicit InvokeServerHandleClientMessageSink(std::unique_ptr<UPSIRpc::Stub> stub)
            : stub_(std::move(stub)) {}

        ~InvokeServerHandleClientMessageSink() override = default;

        Status Send(const ClientMessage& message) override {
            ::grpc::ClientContext client_context;
            client_context.set_deadline(std::chrono::system_clock::time_point::max());

            ::grpc::Status grpc_status = stub_->Handle(
                &client_context,
                message,
                &last_server_response_
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

        const ServerMessage& last_server_response() { return last_server_response_; }

        private:
            std::unique_ptr<UPSIRpc::Stub> stub_;
            ServerMessage last_server_response_;
    };

    Status RunPartyZero() {
        Context context;

        // read in dataset
        std::cout << "[PartyZero] loading data" << std::endl;
        ASSIGN_OR_RETURN(
            auto dataset,
            ReadPartyZeroDataset(
                absl::GetFlag(FLAGS_dir),
                absl::GetFlag(FLAGS_prefix),
                absl::GetFlag(FLAGS_days),
                &context
            )
        );

        std::unique_ptr<PartyZeroImpl> party_zero = std::make_unique<PartyZeroImpl>(
            &context,
            absl::GetFlag(FLAGS_pk_fn),
            absl::GetFlag(FLAGS_sk_fn),
            std::move(dataset),
            absl::GetFlag(FLAGS_paillier_modulus_size),
            absl::GetFlag(FLAGS_paillier_statistical_param),
            absl::GetFlag(FLAGS_days)
        );

        ::grpc::ChannelArguments args;
        args.SetInt(GRPC_ARG_MAX_RECEIVE_MESSAGE_LENGTH, 1024 * 1024 * 1024);

        // setup connection with other party
        std::unique_ptr<UPSIRpc::Stub> stub = UPSIRpc::NewStub(::grpc::CreateCustomChannel(
            absl::GetFlag(FLAGS_port),
            ::grpc::experimental::LocalCredentials(
                grpc_local_connect_type::LOCAL_TCP
            ),
            args
        ));
        InvokeServerHandleClientMessageSink sink(std::move(stub));

        Timer timer("[PartyZero] total runtime");
        for (int i = 0; i < absl::GetFlag(FLAGS_days); i++) {
            std::clog << "[PartyZero] sending request" << std::endl;
            RETURN_IF_ERROR(party_zero->SendMessageI(&sink));

            std::clog << "[PartyZero] waiting for response... ";
            ServerMessage message_ii = sink.last_server_response();
            std::clog << "done." << std::endl;

            std::clog << "[PartyZero] processing response" << std::endl;
            RETURN_IF_ERROR(party_zero->Handle(message_ii, &sink));
    }
    timer.stop();

    std::cout << "[PartyZero] cardinality = " << party_zero->cardinality << std::endl;

    return OkStatus();
}

}  // namespace
}  // namespace upsi

int main(int argc, char** argv) {
    absl::ParseCommandLine(argc, argv);

    if (!DEBUG) { std::clog.setstate(std::ios_base::failbit); }

    auto status = upsi::RunPartyZero();

    std::clog.clear();

    if (!status.ok()) {
        std::cerr << "[PartyZero] failure " << std::endl;
        std::cerr << status << std::endl;
        return 1;
    }

    return 0;
}
