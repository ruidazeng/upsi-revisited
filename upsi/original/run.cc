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
#include "upsi/original/party_one.h"
#include "upsi/original/party_zero.h"
#include "upsi/network/connection.h"
#include "upsi/roles.h"
#include "upsi/network/service.h"
#include "upsi/network/upsi.grpc.pb.h"
#include "upsi/network/upsi.pb.h"
#include "upsi/util/status.inc"
#include "upsi/util/data_util.h"
#include "upsi/utils.h"

using namespace upsi;
using namespace upsi::original;

ABSL_FLAG(int, party, 1, "which party to run");
ABSL_FLAG(std::string, port, "0.0.0.0:10501", "listening port");
ABSL_FLAG(std::string, data_dir, "data/", "name of directory for dataset files");
ABSL_FLAG(std::string, out_dir, "out/", "name of directory for setup files");
ABSL_FLAG(upsi::Functionality, func, upsi::Functionality::PSI, "desired protocol functionality");
ABSL_FLAG(int, days, 10, "total days the protocol will run for");

ABSL_FLAG(bool, trees, false, "use initial trees stored on disk");
ABSL_FLAG(int, start_size, -1, "size of the initial trees (if creating random)");

Status RunPartyZero() {
    Context context;

    PSIParams params(
        true, &context,
        absl::GetFlag(FLAGS_out_dir) + "p0/elgamal.pub",
        absl::GetFlag(FLAGS_out_dir) + "p1/elgamal.pub",
        absl::GetFlag(FLAGS_out_dir) + "p0/elgamal.key",
        absl::GetFlag(FLAGS_days)
    );
    
    params.start_size = absl::GetFlag(FLAGS_start_size);

    if (absl::GetFlag(FLAGS_trees)) {
        params.my_tree_fn = absl::GetFlag(FLAGS_data_dir) + "p0/encrypted.tree";
        params.oprf_fn = absl::GetFlag(FLAGS_data_dir) + "p0/elements.ec";
    }

    // read in dataset
    auto dataset = ReadDailyDatasets(
        &context, absl::GetFlag(FLAGS_data_dir) + "p0/", absl::GetFlag(FLAGS_days)
    );

    std::shared_ptr<PartyZero> party_zero = std::make_shared<PartyZero>(&params, dataset);

    // setup connection
    UPSIService service(party_zero);
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
        std::cout << "[PartyZero] listening on " << absl::GetFlag(FLAGS_port) << std::endl;
        grpc_server_ptr->Wait();
    }, grpc_server.get());

    while (!service.ProtocolFinished()) { }

    std::this_thread::sleep_for(std::chrono::seconds(1));

    party_zero->PrintComm();
    party_zero->PrintResult();

    // shut down server
    grpc_server->Shutdown();
    grpc_server_thread.join();

    std::cout << "[PartyOne] completed protocol and shut down" << std::endl;

    return OkStatus();
}

Status RunPartyOne() {
    Context context;

    PSIParams params(
        true, &context,
        absl::GetFlag(FLAGS_out_dir) + "p1/elgamal.pub",
        absl::GetFlag(FLAGS_out_dir) + "p0/elgamal.pub",
        absl::GetFlag(FLAGS_out_dir) + "p1/elgamal.key",
        absl::GetFlag(FLAGS_days)
    );

    params.start_size = absl::GetFlag(FLAGS_start_size);
    
    if (absl::GetFlag(FLAGS_trees)) {
        params.my_tree_fn = absl::GetFlag(FLAGS_data_dir) + "p1/plaintext.tree";
    }

    // read in dataset
    auto dataset = ReadDailyDatasets(
        &context, absl::GetFlag(FLAGS_data_dir) + "p1/", absl::GetFlag(FLAGS_days)
    );

    std::unique_ptr<PartyOne> party_one = std::make_unique<PartyOne>(&params, std::move(dataset));

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

    std::cout << "[PartyOne] starting protocol" << std::endl;
    RETURN_IF_ERROR(party_one->Run(&sink));

    return OkStatus();
}

int main(int argc, char** argv) {
	srand((unsigned)time(NULL));
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
