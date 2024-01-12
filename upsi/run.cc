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
#include "include/grpcpp/support/status.h"
#include "upsi/connection.h"
#include "upsi/data_util.h"
#include "upsi/party_one.h"
#include "upsi/party_zero.h"
#include "upsi/upsi.grpc.pb.h"
#include "upsi/upsi.pb.h"
#include "upsi/upsi_rpc_impl.h"
#include "upsi/util/status.inc"
#include "upsi/utils.h"
#include "emp-sh2pc/emp-sh2pc.h"

using namespace upsi;

ABSL_FLAG(int, party, 1, "which party to run");
ABSL_FLAG(std::string, port, "0.0.0.0:1026", "listening port");
ABSL_FLAG(std::string, gc_IP, "127.0.0.1", "garbled circuit IP");
ABSL_FLAG(int, gc_port, 1025, "garbled circuit port");
ABSL_FLAG(std::string, dir, "data/", "name of directory for dataset files");
ABSL_FLAG(upsi::Functionality, func, upsi::Functionality::SUM, "desired protocol functionality");
ABSL_FLAG(int, days, (1<<8), "total days the protocol will run for");

Status RunPartyZero() {
    Context context;

    std::string prefix = "party_zero";
    //std::string epk_fn = "shared.epub";
    //std::string esk_fn = prefix + ".ekey";
    std::string psk_fn = prefix + ".pskey";
    std::string ppk_fn = prefix + ".ppkey";

    // read in dataset
    ASSIGN_OR_RETURN(
        auto dataset,
        ReadPartyZeroDataset(
            absl::GetFlag(FLAGS_dir),
            prefix,
            absl::GetFlag(FLAGS_days),
            &context
        )
    );
    
    std::unique_ptr<PartyZero> party_zero;
    switch (absl::GetFlag(FLAGS_func)) {
        /*case Functionality::PSI:
            party_zero = std::make_unique<PartyZeroPSI>(
                &context, ppk_fn, absl::GetFlag(FLAGS_days)
            );
            break;*/
        case Functionality::CA:
            party_zero = std::make_unique<PartyZeroCardinality>(
                &context, psk_fn, ppk_fn, absl::GetFlag(FLAGS_days)
            );
            break;
        case Functionality::SUM:
            party_zero = std::make_unique<PartyZeroSum>(
                &context, psk_fn, ppk_fn, absl::GetFlag(FLAGS_days)
            );
            break;
        default:
            return InvalidArgumentError("unimplemented functionality");
    }
	
    //std::cerr<<"load dataset...\n";
    party_zero->LoadData(dataset);
    party_zero->GarbledCircuitPartySetup(GC_P0);

    ::grpc::ChannelArguments args;
    args.SetInt(GRPC_ARG_MAX_RECEIVE_MESSAGE_LENGTH, 1024 * 1024 * 1024);

    std::cout << "[PartyZero] starting protocol" << std::endl;
    Timer timer("[PartyZero] Total");
    Timer daily("[PartyZero] Daily");
    Timer garbled("[PartyZero] Garbled Circuit");
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
		Timer first_phase("[PartyZero] first phase");
        daily.lap();
    	RETURN_IF_ERROR(party_zero->Run(&sink));
    	daily.stop(); 
    	first_phase.stop();
    	
		emp::NetIO * gc_io = new emp::NetIO("127.0.0.1", absl::GetFlag(FLAGS_gc_port));
		gc_io->set_nodelay();
		Timer second_phase("[PartyZero] second phase");
        garbled.lap();
		party_zero->GarbledCircuitIOSetup(gc_io);
    	ASSIGN_OR_RETURN(uint64_t rs, party_zero->GarbledCircuit());
    	uint64_t other_rs;
    	gc_io->recv_data(&other_rs, sizeof(uint64_t));
    	party_zero->UpdateResult(rs + other_rs);
        garbled.stop();
        second_phase.stop();
    	party_zero->PrintResult();
    	delete gc_io;
    }
    daily.print();
    garbled.print();
    timer.stop();
    party_zero->PrintResult();
    

    return OkStatus();
}

Status RunPartyOne() {
    Context context;

    std::string prefix = "party_one";/*
    std::string epk_fn = "shared.epub";
    std::string esk_fn = prefix + ".ekey";*/
    std::string psk_fn = prefix + ".pskey";
    std::string ppk_fn = prefix + ".ppkey";

    // read in dataset
    ASSIGN_OR_RETURN(
        auto dataset,
        ReadPartyOneDataset(
            absl::GetFlag(FLAGS_dir),
            prefix,
            absl::GetFlag(FLAGS_days),
            &context
        )
    );
    
    std::unique_ptr<PartyOne> party_one;
    switch (absl::GetFlag(FLAGS_func)) {
        /*case Functionality::PSI:
            party_one = std::make_unique<PartyOnePSI>(
                &context, ppk_fn, absl::GetFlag(FLAGS_days)
            );
            break;*/
        case Functionality::CA:
            party_one = std::make_unique<PartyOneCASUM>(
                &context, psk_fn, ppk_fn, absl::GetFlag(FLAGS_days)
            );
            break;
        case Functionality::SUM:
            party_one = std::make_unique<PartyOneCASUM>(
                &context, psk_fn, ppk_fn, absl::GetFlag(FLAGS_days)
            );
            break;
        default:
            return InvalidArgumentError("unimplemented functionality");
    }
	
	//std::cerr<<"load dataset...\n";
    party_one->LoadData(dataset);
    party_one->GarbledCircuitPartySetup(GC_P1);
    
    int total_days = absl::GetFlag(FLAGS_days);
    for (int i = 0; i < total_days; ++i) {
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
    
		// Run the server on a background thread.
		std::thread grpc_server_thread([](::grpc::Server* grpc_server_ptr) {
		    std::cout << "[PartyOne] listening on " << absl::GetFlag(FLAGS_port) << std::endl;
		    grpc_server_ptr->Wait();
		}, grpc_server.get());
    	service.new_day();

		while (!service.day_finished())
		std::this_thread::sleep_for(std::chrono::seconds(1));

		// shut down server
		grpc_server->Shutdown();
		grpc_server_thread.join();
		
		party_one = service.getPartyOne();
		
		emp::NetIO * gc_io = new emp::NetIO(nullptr, absl::GetFlag(FLAGS_gc_port));
		gc_io->set_nodelay();
		party_one->GarbledCircuitIOSetup(gc_io);
		
		ASSIGN_OR_RETURN(uint64_t rs, party_one->GarbledCircuit());
		gc_io->send_data(&rs, sizeof(uint64_t));
    	delete gc_io;
	}
    std::cout << "[PartyOne] completed protocol and shut down" << std::endl;
    

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
