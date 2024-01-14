#ifndef PARTY_H_
#define PARTY_H_

#include "upsi/crypto/elgamal.h"
#include "upsi/crypto/threshold_paillier.h"
#include "upsi/util/elgamal_proto_util.h"
#include "upsi/util/proto_util.h"
#include "upsi/utils.h"
#include "emp-sh2pc/emp-sh2pc.h"

namespace upsi {

class Party { 
    protected:
        // used for various crypto operations
        Context* ctx_;
        ECGroup* group;
        
        //garbled circuit IO
        emp::NetIO * gc_io_;
        emp::IKNP<NetIO> * ot_sender, *ot_receiver;

        // paillier encryption tool
        std::unique_ptr<PrivatePaillier> my_paillier;
        std::unique_ptr<PublicPaillier> other_paillier;
        std::vector<uint64_t> gc_x, gc_y;
        std::vector<BigNum> gc_z;

        // to keep track of time
        int total_days;
        int gc_party;
        
        
        // our plaintext tree & their encrypted tree
        CryptoTree<ElementAndPayload> my_tree;
        CryptoTree<CiphertextAndPayload> other_tree;

    public: 
        int current_day = 0;
        /**
         * instantiate a party
         * psk_fn   : filename for paillier key
         */
        Party(
            Context* ctx,
            std::string psk_fn,
            std::string ppk_fn,
            int total_days
        ) {
            this->ctx_ = ctx;

            this->total_days = total_days;

            // set up keys
            auto group = new ECGroup(ECGroup::Create(CURVE_ID, ctx).value());
            this->group = group; // TODO: delete
            
            
            auto my_psk = ProtoUtils::ReadProtoFromFile<PaillierPrivateKey>(psk_fn);
            if (!my_psk.ok()) {
                std::runtime_error("[Party] failure in reading paillier key");
            }
			
            auto my_key = PaillierPrivateKey(my_psk.value());
			
			this->my_paillier = std::make_unique<PrivatePaillier>(this->ctx_, my_key);

            auto other_ppk = ProtoUtils::ReadProtoFromFile<PaillierPublicKey>(ppk_fn);
            if (!other_ppk.ok()) {
                std::runtime_error("[Party] failure in reading paillier key");
            }

            auto other_key = std::make_unique<PaillierPublicKey>(other_ppk.value());
            
            this->other_paillier = std::make_unique<PublicPaillier>(this->ctx_, ctx_->CreateBigNum(other_key->n()));
        }
        
        void GarbledCircuitPartySetup(int gc_p) {this->gc_party = gc_p;}
        void GarbledCircuitIOSetup(emp::NetIO * io, emp::IKNP<NetIO> * ot_s, emp::IKNP<NetIO> * ot_r) {this->gc_io_ = io; this->ot_sender = ot_s, this->ot_receiver = ot_r;}
        
        void ResetGarbledCircuit() {
        	gc_x.clear();
        	gc_y.clear();
        	gc_z.clear();
        }
        
        StatusOr<std::vector<Element> > CombinePathInitiator(ElementAndPayload element) {

			std::vector<CiphertextAndPayload> path = this->other_tree.getPath(element.first);
			std::vector<Element> res;
			BigNum value = element.second;
			if(!element.second.IsNonNegative()) //negative
				value = element.second + other_paillier->n();
				
			for (const CiphertextAndPayload& path_i: path) {
				BigNum alpha = this->ctx_->GenerateRandLessThan(other_paillier->n());
				gc_x.push_back(BigNum2uint64(alpha));
				
				ASSIGN_OR_RETURN(BigNum alpha_minus_x, other_paillier->Encrypt(alpha - element.first)); //alpha >> element
				BigNum tmp = other_paillier->Add(alpha_minus_x, path_i.first);//y - x + alpha
				
				if(element.second != this->ctx_->One()) {
					BigNum p_times_q = other_paillier->Multiply(path_i.second, value);
					gc_z.push_back(p_times_q);
				}
				else {
					gc_z.push_back(path_i.second);
				}
				
				res.push_back(tmp);
			}
			
			return res;
		}
		
		Status CombinePathResponder(std::vector<Element> elements) {
				
			for (const Element& elements_i: elements) {
				ASSIGN_OR_RETURN(BigNum tmp, my_paillier->Decrypt(elements_i));
				gc_y.push_back(BigNum2uint64(tmp)); 
			}
			
			return OkStatus();
		}
		
		StatusOr<uint64_t> GarbledCircuit(bool is_sender) {
			int cnt;
			if(is_sender) cnt = gc_x.size();
			else cnt = gc_y.size();
			
			std::vector<bool> my_bit;
			
			for (int i = 0; i < cnt; ++i) {
				Bit eq(true);
				emp::Integer a(64, is_sender? gc_x[i] : gc_y[i], emp::ALICE);
				emp::Integer b(64, is_sender? gc_x[i] : gc_y[i], emp::BOB);
				
				bool cur_bit = 0;
				if(gc_party == emp::ALICE) cur_bit = rand() & 1;
				emp::Bit tmp(cur_bit ^ 1, emp::ALICE);
				
				eq = (a == b);
				//if(eq.reveal()) std::cerr<<"# " << i << "\n";
				eq = eq ^ tmp;
				
				if(gc_party == emp::ALICE) eq.reveal(emp::BOB);
				else cur_bit = eq.reveal(emp::BOB);
				
				my_bit.push_back(cur_bit);
			}
			
			BigNum rs = ctx_->Zero();
			
			int len = 0, cnt_block = 0;
			BigNum cur_n = ctx_->Zero();
			if(is_sender) cur_n = other_paillier->n();
			else cur_n = my_paillier->n();
			
			len = cur_n.ToBytes().length();
			
			cnt_block = (len * 2 + 15) >> 4; // ceil(len*2/16)
			
			bool chosen_bit[cnt_block];
			
			emp::block block_eq[cnt_block];
			emp::block block_neq[cnt_block];
			
			//std::cerr << cnt_block << " " << cnt << std::endl;
			for (int i = 0; i < cnt; ++i) {
				if(is_sender) {
					BigNum beta = this->ctx_->GenerateRandLessThan(cur_n);
					//BigNum beta = this->ctx_->Zero();
					ASSIGN_OR_RETURN(BigNum encrypted_beta, other_paillier->Encrypt(cur_n - beta));
					//ASSIGN_OR_RETURN(BigNum encrypted_beta, other_paillier->Encrypt(beta));
					BigNum if_eq = other_paillier->Add(gc_z[i], encrypted_beta);
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
					
					if(my_bit[i] == 0) ot_sender->send(block_eq, block_neq, cnt_block);
					else ot_sender->send(block_neq, block_eq, cnt_block);
					rs = rs + beta;
				}
				else {
					memset(chosen_bit, my_bit[i], sizeof(chosen_bit));
					ot_receiver->recv(block_eq, chosen_bit, cnt_block);
					/*
					std::cerr << cnt_block << std::endl;
					for (int j = 0; j < cnt_block; ++j) {emp::operator<<(std::cerr, block_eq[j]); std::cerr << " ";}
					std::cerr << "\n";*/
					
					//std::cerr << (my_bit[i] ^ 1);
					
					ASSIGN_OR_RETURN(BigNum tmp, my_paillier->Decrypt(block2BigNum(block_eq, cnt_block, ctx_)));
					
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
				//std::cerr<<"positive\n";
				rs_ = BigNum2uint64(rs);
			}
			//std::cerr<<(long long)rs_<<std::endl;
				
			return rs_;
		}
		
		StatusOr<uint64_t> GarbledCircuit() {
			//std::cerr<<"garbled circuit...\n";
			uint64_t rs1, rs2;
			if(gc_party == emp::ALICE) {
				ASSIGN_OR_RETURN(rs1, GarbledCircuit(false));
				ASSIGN_OR_RETURN(rs2, GarbledCircuit(true));
			}
			else {
				ASSIGN_OR_RETURN(rs1, GarbledCircuit(true));
				ASSIGN_OR_RETURN(rs2, GarbledCircuit(false));
			}
			return rs1 + rs2;
		}

        // call once the day is finished for this party
        virtual void FinishDay() {
            this->current_day++;
        }

        // protocol is finished when we've gone through all days
        virtual bool protocol_finished() {
            return (this->current_day >= this->total_days);
        }
};

} // namespace upsi

#endif  // PARTY_H_
