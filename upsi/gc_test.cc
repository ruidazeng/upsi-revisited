#include "emp-sh2pc/emp-sh2pc.h"
#include "upsi/utils.h"
using namespace emp;
using namespace upsi;
using namespace std;

const int SIZE = 1e4+7;
const int cnt = 1e4;

void lookup(int party, uint64_t* x, uint64_t* y, uint64_t* ans) {
	for (int i = 0; i < cnt; ++i) {
		Integer a(64, x[i], ALICE);
		Integer b(64, x[i], BOB);
		Integer A(64, y[i], ALICE);
		Integer B(64, y[i], BOB);
		
		if(party == ALICE) ans[i] = ((uint64_t)rand()<<32)+ rand();
		Integer rs(64, ans[i], ALICE);
		Integer zro(64, 0, BOB);
		Bit eq = (a == b);
		Integer C = A + B;
		Integer totrs = zro.select(eq, C);
		Integer rs_bob = totrs - rs;
		if(party == ALICE) rs_bob.reveal<uint64_t>(BOB);
		else ans[i] = rs_bob.reveal<uint64_t>(BOB);
	}
}

void test_OT() {
	Context ctx;
	BigNum cur = ctx.CreateBigNum(23472349);
	block cur_block[2];
	BigNum2block(cur, cur_block, 2);
	BigNum tmp = block2BigNum(cur_block, 2, &ctx);
	if(tmp != cur) {
		std::cerr<<"!!!\n";
		assert(0);
	}
}

int main(int argc, char** argv) {
	int port, party;
	parse_party_and_port(argv, &party, &port);
	
	test_OT();
	
	/*
	NetIO * io = new NetIO(party==ALICE ? nullptr : "127.0.0.1", port);
	
	uint64_t *x = new uint64_t[SIZE], *y = new uint64_t[SIZE], *ans = new uint64_t[SIZE];
	srand((unsigned)time(NULL));
	for (int i = 0; i < cnt; ++i) {
		x[i] = rand() % 10;
		y[i] = rand();
	}
	setup_semi_honest(io, party);
	std::cerr<<"semi honest setup\n";
	upsi::Timer timer("Garbled Circuit");
	//if xA = xB: output [yA + yB], else output[0]
	lookup(party, x, y, ans);
        timer.stop();
        //timer.print();
	
	
	delete[] x;
	delete[] y;
	delete[] ans;
	cout << "num_and: "<< CircuitExecution::circ_exec->num_and()<<endl;
	finalize_semi_honest();
	delete io;*/
	return 0;
}
