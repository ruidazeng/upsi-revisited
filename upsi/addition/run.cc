#include <chrono>
#include <iostream>
#include <memory>
#include <ostream>
#include <string>
#include <thread>  // NOLINT
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
#include "include/grpcpp/security/server_credentials.h"
#include "include/grpcpp/server_builder.h"
#include "include/grpcpp/server_context.h"
#include "include/grpcpp/support/status.h"
#include "upsi/addition/party_one.h"
#include "upsi/addition/party_zero.h"
#include "upsi/network/connection.h"
#include "upsi/roles.h"
#include "upsi/network/service.h"
#include "upsi/network/upsi.grpc.pb.h"
#include "upsi/network/upsi.pb.h"
#include "upsi/util/status.inc"
#include "upsi/util/data_util.h"
#include "upsi/utils.h"

using namespace upsi;
using namespace upsi::addonly;

ABSL_FLAG(int, party, 1, "which party to run");
ABSL_FLAG(std::string, port, "0.0.0.0:10501", "listening port");
ABSL_FLAG(std::string, data_dir, "data/", "name of directory for dataset files");
ABSL_FLAG(std::string, out_dir, "out/", "name of directory for setup files");
ABSL_FLAG(upsi::Functionality, func, upsi::Functionality::SUM, "desired protocol functionality");
ABSL_FLAG(int, days, 10, "total days the protocol will run for");

ABSL_FLAG(bool, trees, true, "use initial trees stored on disk");

Status RunPartyZero() {
    Context context;

    PSIParams params(
        &context,
        absl::GetFlag(FLAGS_out_dir) + "p0/shared.pub",
        absl::GetFlag(FLAGS_out_dir) + "p0/elgamal.key",
        absl::GetFlag(FLAGS_out_dir) + "p0/paillier.key",
        absl::GetFlag(FLAGS_days)
    );

    if (absl::GetFlag(FLAGS_trees)) {
        params.my_tree_fn = absl::GetFlag(FLAGS_data_dir) + "p0/plaintext";
        params.other_tree_fn = absl::GetFlag(FLAGS_data_dir) + "p0/encrypted";
    }

    // read in dataset
    auto dataset = ReadDailyDatasets(
        &context, absl::GetFlag(FLAGS_data_dir) + "p0/", absl::GetFlag(FLAGS_days)
    );

    std::unique_ptr<PartyZero> party_zero;
    switch (absl::GetFlag(FLAGS_func)) {
        case Functionality::PSI:
            party_zero = std::make_unique<PartyZeroPSI>(&params);
            break;
        case Functionality::CA:
            party_zero = std::make_unique<PartyZeroCardinality>(&params);
            break;
        case Functionality::SUM:
            party_zero = std::make_unique<PartyZeroSum>(&params);
            break;
        case Functionality::SS:
            party_zero = std::make_unique<PartyZeroSecretShare>(&params);
            break;
        default:
            return InvalidArgumentError("unimplemented functionality");
    }
    party_zero->LoadData(dataset);

    ::grpc::ChannelArguments args;
    args.SetInt(GRPC_ARG_MAX_RECEIVE_MESSAGE_LENGTH, 1024 * 1024 * 1024);

    // setup connection with other party
    std::unique_ptr<UPSIRpc::Stub> stub = UPSIRpc::NewStub(
        ::grpc::CreateCustomChannel(
            absl::GetFlag(FLAGS_port),
            ::grpc::experimental::LocalCredentials(grpc_local_connect_type::LOCAL_TCP),
            args
        )
    );
    Connection sink(std::move(stub));

    std::cout << "[PartyZero] starting protocol" << std::endl;
    RETURN_IF_ERROR(party_zero->Run(&sink));
    party_zero->PrintResult();

    return OkStatus();
}

Status RunPartyOne() {
    Context context;

    PSIParams params(
        &context,
        absl::GetFlag(FLAGS_out_dir) + "p1/shared.pub",
        absl::GetFlag(FLAGS_out_dir) + "p1/elgamal.key",
        absl::GetFlag(FLAGS_out_dir) + "p1/paillier.key",
        absl::GetFlag(FLAGS_days)
    );

    if (absl::GetFlag(FLAGS_trees)) {
        params.my_tree_fn = absl::GetFlag(FLAGS_data_dir) + "p1/plaintext";
        params.other_tree_fn = absl::GetFlag(FLAGS_data_dir) + "p1/encrypted";
    }

    // read in dataset
    auto dataset = ReadDailyDatasets(
        &context, absl::GetFlag(FLAGS_data_dir) + "p1/", absl::GetFlag(FLAGS_days)
    );

    std::shared_ptr<PartyOne> party_one;
    switch (absl::GetFlag(FLAGS_func)) {
        case Functionality::PSI:
            party_one = std::make_unique<PartyOnePSI>(&params, std::move(dataset));
            break;
        case Functionality::CA:
            party_one = std::make_unique<PartyOneCardinality>(&params, std::move(dataset));
            break;
        case Functionality::SUM:
            party_one = std::make_unique<PartyOneSum>(&params, std::move(dataset));
            break;
        case Functionality::SS:
            party_one = std::make_unique<PartyOneSecretShare>(&params, std::move(dataset));
            break;
        default:
            return InvalidArgumentError("unimplemented functionality");
    }
    // setup connection
    UPSIService service(party_one);
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

    // Run the server on a background thread.
    std::thread grpc_server_thread([](::grpc::Server* grpc_server_ptr) {
        std::cout << "[PartyOne] listening on " << absl::GetFlag(FLAGS_port) << std::endl;
        grpc_server_ptr->Wait();
    }, grpc_server.get());

    while (!service.ProtocolFinished()) { }

    party_one->PrintComm();
    party_one->PrintResult();

    // shut down server
    grpc_server->Shutdown();
    grpc_server_thread.join();

    std::cout << "[PartyOne] completed protocol and shut down" << std::endl;

    return OkStatus();
}

int main(int argc, char** argv) {
    absl::ParseCommandLine(argc, argv);

    if (!DEBUG) { std::clog.setstate(std::ios_base::failbit); }

    Status status = OkStatus();

    if (absl::GetFlag(FLAGS_party) == 0) {
        status = RunPartyZero();
    } else {
        status = RunPartyOne();
    }

    std::clog.clear();

    if (!status.ok()) {
        std::cerr << "[Run] failure " << std::endl;
        std::cerr << status << std::endl;
        return 1;
    }

    return 0;
}
