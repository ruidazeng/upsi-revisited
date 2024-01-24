
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

#include "upsi/deletion-psi/party_one.h"
#include "upsi/deletion-psi/party_zero.h"
#include "upsi/network/connection.h"
#include "upsi/network/service.h"
#include "upsi/network/upsi.grpc.pb.h"
#include "upsi/network/upsi.pb.h"
#include "upsi/util/data_util.h"
#include "upsi/util/status.inc"
#include "upsi/utils.h"
#include "emp-sh2pc/emp-sh2pc.h"

using namespace upsi;
using namespace upsi::deletion_psi;

ABSL_FLAG(int, party, 1, "which party to run");
ABSL_FLAG(std::string, port, "0.0.0.0:1026", "listening port");
ABSL_FLAG(std::string, gc_IP, "127.0.0.1", "garbled circuit IP");
ABSL_FLAG(int, gc_port, 1025, "garbled circuit port");
ABSL_FLAG(std::string, data_dir, "data/", "name of directory for dataset files");
ABSL_FLAG(std::string, out_dir, "out/", "name of directory for setup files");
ABSL_FLAG(upsi::Functionality, func, upsi::Functionality::PSI, "desired protocol functionality");
ABSL_FLAG(int, days, 10, "total days the protocol will run for");

ABSL_FLAG(bool, trees, true, "use initial trees stored on disk");

Status RunPartyZero() {
    Context context;

    PSIParams params(
        &context,
        absl::GetFlag(FLAGS_out_dir) + "p0/paillier.pub",
        absl::GetFlag(FLAGS_out_dir) + "p0/paillier.key",
        absl::GetFlag(FLAGS_days)
    );

    if (absl::GetFlag(FLAGS_trees)) {
        params.my_tree_fn = absl::GetFlag(FLAGS_data_dir) + "p0/plaintext.tree";
        params.other_tree_fn = absl::GetFlag(FLAGS_data_dir) + "p0/encrypted.tree";
    }

    // read in dataset
    auto dataset = ReadDailyDatasets(
        &context, absl::GetFlag(FLAGS_data_dir) + "p0/", absl::GetFlag(FLAGS_days)
    );

    std::unique_ptr<PartyZero> party_zero;
    switch (absl::GetFlag(FLAGS_func)) {
        case Functionality::PSI:
            party_zero = std::make_unique<PartyZero>(&params);
            break;
        default:
            return InvalidArgumentError("unimplemented functionality");
    }
    party_zero->LoadData(dataset);

    ::grpc::ChannelArguments args;
    args.SetInt(GRPC_ARG_MAX_RECEIVE_MESSAGE_LENGTH, 1024 * 1024 * 1024);

	emp::NetIO * gc_io = new emp::NetIO("127.0.0.1", absl::GetFlag(FLAGS_gc_port));
	emp::IKNP<NetIO> * ot_s = new emp::IKNP<NetIO>(gc_io);
	emp::IKNP<NetIO> * ot_r = new emp::IKNP<NetIO>(gc_io);
	party_zero->GarbledCircuitIOSetup(gc_io, ot_s, ot_r);
	emp::setup_semi_honest(gc_io, emp::BOB);

    gc_io->flush();

    std::cout << "[PartyZero] starting protocol" << std::endl;
    Timer daily("[PartyZero] Daily Comp");
    Timer grpc("[PartyZero] Updates & Prep");
    Timer garbled("[PartyZero] GCs & OTs");
    int total_days = absl::GetFlag(FLAGS_days);
    for (int i = 0; i < total_days; ++i) {
		std::this_thread::sleep_for(std::chrono::seconds(1));
		// setup connection with other party
		std::unique_ptr<UPSIRpc::Stub> stub = UPSIRpc::NewStub(::grpc::CreateCustomChannel(
		        absl::GetFlag(FLAGS_port),
		        ::grpc::experimental::LocalCredentials(
		            grpc_local_connect_type::LOCAL_TCP
		        ),
		        args
		));
		Connection sink(std::move(stub));
		Timer day("[PartyZero] Day " + std::to_string(i) + " Comp");
        daily.lap();
        grpc.lap();
    	RETURN_IF_ERROR(party_zero->Run(&sink));
    	grpc.stop();

        garbled.lap();
    	RETURN_IF_ERROR(party_zero->SecondPhase());
       	party_zero->StoreCommGC(i);
        garbled.stop();
        daily.stop();
        day.stop();
    }
    grpc.print();
    garbled.print();
    daily.print();
    
    party_zero->PrintResult();
    party_zero->PrintComm();

	finalize_semi_honest();
    delete gc_io;
    delete ot_s;
    delete ot_r;

    return OkStatus();
}

Status RunPartyOne() {
    Context context;

    PSIParams params(
        &context,
        absl::GetFlag(FLAGS_out_dir) + "p1/paillier.pub",
        absl::GetFlag(FLAGS_out_dir) + "p1/paillier.key",
        absl::GetFlag(FLAGS_days)
    );

    if (absl::GetFlag(FLAGS_trees)) {
        params.my_tree_fn = absl::GetFlag(FLAGS_data_dir) + "p1/plaintext.tree";
        params.other_tree_fn = absl::GetFlag(FLAGS_data_dir) + "p1/encrypted.tree";
    }

    // read in dataset
    auto dataset = ReadDailyDatasets(
        &context, absl::GetFlag(FLAGS_data_dir) + "p1/", absl::GetFlag(FLAGS_days)
    );

    std::shared_ptr<PartyOne> party_one;
    switch (absl::GetFlag(FLAGS_func)) {
        case Functionality::PSI:
            party_one = std::make_unique<PartyOne>(&params, dataset);
            break;
        default:
            return InvalidArgumentError("unimplemented functionality");
    }

    emp::NetIO * gc_io = new emp::NetIO(nullptr, absl::GetFlag(FLAGS_gc_port));
    //gc_io->set_nodelay();
    emp::IKNP<NetIO> * ot_s = new emp::IKNP<NetIO>(gc_io);
    emp::IKNP<NetIO> * ot_r = new emp::IKNP<NetIO>(gc_io);
    party_one->GarbledCircuitIOSetup(gc_io, ot_s, ot_r);
    emp::setup_semi_honest(gc_io, emp::ALICE);
    gc_io->flush();

    int total_days = absl::GetFlag(FLAGS_days);
    for (int i = 0; i < total_days; ++i) {
        party_one->Reset();
        party_one->ResetGarbledCircuit();

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
        // service.new_day();

        while (!service.ProtocolFinished());
        
        std::this_thread::sleep_for(std::chrono::seconds(2));

        // shut down server
        grpc_server->Shutdown();
        grpc_server_thread.join();

    	RETURN_IF_ERROR(party_one->SecondPhase());
    	party_one->StoreCommGC(i);
       
    }
    std::cout << "[PartyOne] completed protocol and shut down" << std::endl;
    
    party_one->PrintComm();

	finalize_semi_honest();
    delete gc_io;
    delete ot_s;
    delete ot_r;

    return OkStatus();
}

int main(int argc, char** argv) {
    absl::ParseCommandLine(argc, argv);

    srand((unsigned)time(NULL));

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
