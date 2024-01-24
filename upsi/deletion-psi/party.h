#pragma once

#include "emp-sh2pc/emp-sh2pc.h"

#include "upsi/crypto/paillier.h"
#include "upsi/roles.h"
#include "upsi/util/gc_util.h"
#include "upsi/util/proto_util.h"
#include "upsi/utils.h"

namespace upsi {
namespace deletion_psi {

class Party : public HasTree<ElementAndPayload, PaillierPair> {
    protected:
        // one dataset for each day
        std::vector<std::vector<ElementAndPayload>> datasets[2];

        // networking for garbled circuit
        emp::NetIO * gc_io_;
        emp::IKNP<NetIO> * ot_sender, *ot_receiver;

        // paillier encryption tools
        std::unique_ptr<PrivatePaillier> sk;
        std::unique_ptr<PublicPaillier> pk;

        // garbled circuit inputs inputs and outputs
        std::vector<std::vector<BigNum> > gc_x, gc_y;
        std::vector<std::vector<BigNum> > gc_z;
        
        std::vector<uint64_t> comm_, comm_gc;

        int gc_party;
    public:
        Party(
            PSIParams* params, int gc_party
        ) : HasTree<ElementAndPayload, PaillierPair>(params), gc_party(gc_party), comm_(params->total_days), comm_gc(params->total_days) {
            auto sk = ProtoUtils::ReadProtoFromFile<PaillierPrivateKey>(params->psk_fn);
            if (!sk.ok()) {
                std::runtime_error("[Party] failure in reading paillier secret key");
            }

            this->sk = std::make_unique<PrivatePaillier>(this->ctx_, sk.value());

            auto pk = ProtoUtils::ReadProtoFromFile<PaillierPublicKey>(params->ppk_fn);
            if (!pk.ok()) {
                std::runtime_error("[Party] failure in reading paillier public key");
            }

            this->pk = std::make_unique<PublicPaillier>(this->ctx_, pk.value());
        }
        
        void AddComm(const google::protobuf::Message& msg, int day) {
            comm_[day] += msg.ByteSizeLong();
        }
        
        void StoreCommGC(int day) {
        	comm_gc[day] = gc_io_->counter;
        }
        
        void PrintComm() {
            unsigned long long total = 0, cnt = comm_.size();
            for (size_t day = 0; day < cnt; day++) {
                std::cout << "Day " << std::to_string(day + 1) << " Comm Sent(B):\t";
                std::cout << comm_[day] << "\t + \t";
                if(day == 0) std::cout << comm_gc[day];
                else std::cout << comm_gc[day] - comm_gc[day - 1];
                std::cout << "\n";
                total += comm_[day];
            }
            std::cout << "Total Comm Sent(B):\t" << total + comm_gc[cnt - 1] << std::endl;
        }

        //void GarbledCircuitIOSetup(emp::NetIO* io) {this->gc_io_ = io;}
        void GarbledCircuitIOSetup(emp::NetIO* io, emp::IKNP<NetIO>* ot_s, emp::IKNP<NetIO>* ot_r) {
            this->gc_io_ = io;
            this->ot_sender = ot_s;
            this->ot_receiver = ot_r;
        }

        void ResetGarbledCircuit() {
            gc_x.clear();
            gc_y.clear();
            gc_z.clear();
        }

        StatusOr<std::vector<Element>> CombinePathInitiator(ElementAndPayload element) {

            std::vector<PaillierPair> path = this->other_tree.getPath(element.first);
            std::vector<Element> res;
            BigNum value = element.second;
            if (!element.second.IsNonNegative()) { // negative
                value = element.second + this->pk->n();
            }
			
			std::vector<BigNum> gc_x_tmp;
			std::vector<BigNum> gc_z_tmp;
            for (const PaillierPair& path_i: path) {
                BigNum alpha = this->ctx_->GenerateRandLessThan(this->pk->n());
                gc_x_tmp.push_back(alpha);

                ASSIGN_OR_RETURN(BigNum alpha_minus_x, this->pk->Encrypt(alpha - element.first)); //alpha >> element
                BigNum tmp = this->pk->Add(alpha_minus_x, path_i.first);//y - x + alpha

                if(element.second != this->ctx_->One()) {
                    BigNum p_times_q = this->pk->Multiply(path_i.second, value);
                    gc_z_tmp.push_back(p_times_q);
                }
                else {
                    gc_z_tmp.push_back(path_i.second);
                }
                res.push_back(tmp);
            }
            gc_x.push_back(gc_x_tmp);
            gc_z.push_back(gc_z_tmp);

            return res;
        }

        Status CombinePathResponder(std::vector<std::vector<Element> > elements) {
        	int cnt = elements.size();
        	for (int i = 0; i < cnt; ++i) {
				std::vector<BigNum> gc_y_tmp;
		        for (const Element& elements_i: elements[i]) {
		            ASSIGN_OR_RETURN(BigNum tmp, this->sk->Decrypt(elements_i));
		            gc_y_tmp.push_back(tmp);
		        }
		        
		        gc_y.push_back(gc_y_tmp);
			}
            return OkStatus();
        }

        Status GarbledCircuit(bool is_sender, std::vector<uint64_t>& ans) {
            int cnt;
            if(is_sender) cnt = gc_x.size();
            else cnt = gc_y.size();

            std::vector<std::vector<bool> > my_bit;

            bool bool_val[GC_SIZE];
            for (int i = 0; i < cnt; ++i) {
            	int cnt_vct;
            	if(is_sender) cnt_vct = gc_x[i].size();
            	else cnt_vct = gc_y[i].size();
            	std::vector<bool> my_bit_tmp;
            	for (int j = 0; j < cnt_vct; ++j) {
		            Bit eq(true);
		            if(is_sender) BigNum2bool(gc_x[i][j], bool_val);
		            else BigNum2bool(gc_y[i][j], bool_val);
		            emp::Integer a, b;
		            a.init(bool_val, GC_SIZE, emp::ALICE);
		            b.init(bool_val, GC_SIZE, emp::BOB);

		            bool cur_bit = 0;
		            if(gc_party == emp::ALICE) cur_bit = rand() & 1;
		            emp::Bit tmp(cur_bit ^ 1, emp::ALICE);

		            eq = (a == b);
		            //if(eq.reveal()) std::cerr<<"# " << i << "\n";
		            eq = eq ^ tmp;

		            if(gc_party == emp::ALICE) eq.reveal(emp::BOB);
		            else cur_bit = eq.reveal(emp::BOB);

		            my_bit_tmp.push_back(cur_bit);
		       }
		       my_bit.push_back(my_bit_tmp);
            }
            
            int len = 0, cnt_block = 0;
            BigNum cur_n = ctx_->Zero();
            if(is_sender) cur_n = this->pk->n();
            else cur_n = this->sk->n();

            len = cur_n.ToBytes().length();

            cnt_block = (len * 2 + 15) >> 4; // ceil(len*2/16)

            bool chosen_bit[cnt_block];

            emp::block block_eq[cnt_block];
            emp::block block_neq[cnt_block];

            //std::cerr << cnt_block << " " << cnt << std::endl;
            for (int i = 0; i < cnt; ++i) {
            	BigNum rs = ctx_->Zero();
            	int cnt_vct = my_bit[i].size();
            	for (int j = 0; j < cnt_vct; ++j) {
		            if(is_sender) {
		                BigNum beta = this->ctx_->GenerateRandLessThan(cur_n);
		                //BigNum beta = this->ctx_->Zero();
		                ASSIGN_OR_RETURN(BigNum encrypted_beta, this->pk->Encrypt(cur_n - beta));
		                //ASSIGN_OR_RETURN(BigNum encrypted_beta, this->pk->Encrypt(beta));
		                BigNum if_eq = this->pk->Add(gc_z[i][j], encrypted_beta);
		                //BigNum if_neq = if_eq;
		                BigNum if_neq = encrypted_beta;

		                BigNum2block(if_eq, block_eq, cnt_block);
		                BigNum2block(if_neq, block_neq, cnt_block);
		                /*
		                   std::cerr << cnt_block << std::endl;
		                   for (int j = 0; j < cnt_block; ++j) {emp::operator<<(std::cerr, block_eq[j]); std::cerr << " ";}
		                   std::cerr << "\n";
		                   for (int j = 0; j < cnt_block; ++j) {emp::operator<<(std::cerr, block_neq[j]); std::cerr << " ";}
		                   std::cerr << "\n";*/

		                //std::cerr << my_bit[i];

		                if (my_bit[i][j] == 0) ot_sender->send(block_eq, block_neq, cnt_block);
		                else ot_sender->send(block_neq, block_eq, cnt_block);
		                rs = rs + beta;
		            }
		            else {
		                memset(chosen_bit, my_bit[i][j], sizeof(chosen_bit));
		                ot_receiver->recv(block_eq, chosen_bit, cnt_block);
		                /*
		                   std::cerr << cnt_block << std::endl;
		                   for (int j = 0; j < cnt_block; ++j) {emp::operator<<(std::cerr, block_eq[j]); std::cerr << " ";}
		                   std::cerr << "\n";*/

		                //std::cerr << (my_bit[i] ^ 1);

		                ASSIGN_OR_RETURN(BigNum tmp, this->sk->Decrypt(block2BigNum(block_eq, cnt_block, ctx_)));

		                rs = rs + tmp;
		            }
                }
                rs = rs.Mod(cur_n); //with ?? probability one < cur_n/2, the other > cur_n/2
		        uint64_t rs_ = 0;
		        if((rs * ctx_->Two()) > cur_n) {//negative
		            //std::cerr<<"negative\n";
		            rs_ = BigNum2uint64(cur_n - rs); //positive mod 2^64
		            rs_ = -rs_; //negative mod 2^64
		        }
		        else {
		            rs_ = BigNum2uint64(rs);
		            //std::cerr<<"positive\n";
		        }
		        //std::cerr<<(long long) rs_ << std::endl;
		        ans.push_back(rs_);
            }
            
            return OkStatus();
        }

        StatusOr<std::vector<uint64_t> > GarbledCircuit() {
            std::vector<uint64_t> ans;
            if(gc_party == emp::ALICE) {
                RETURN_IF_ERROR(GarbledCircuit(false, ans));
                RETURN_IF_ERROR(GarbledCircuit(true, ans));
            }
            else {
                RETURN_IF_ERROR(GarbledCircuit(true, ans));
                RETURN_IF_ERROR(GarbledCircuit(false, ans));
            }
            gc_io_->flush();
            return ans;
        }
};

} // namespace deletion_psi
} // namespace upsi
