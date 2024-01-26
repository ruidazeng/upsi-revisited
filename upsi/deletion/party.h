#pragma once

#include "emp-sh2pc/emp-sh2pc.h"

#include "upsi/crypto/paillier.h"
#include "upsi/roles.h"
#include "upsi/util/gc_util.h"
#include "upsi/util/proto_util.h"
#include "upsi/utils.h"

namespace upsi {
namespace deletion {

class Party : public HasTree<ElementAndPayload, PaillierPair> {
    protected:
        // one dataset for each day
        std::vector<std::vector<ElementAndPayload>> datasets;

        // networking for garbled circuit
        emp::NetIO * gc_io_;
        emp::IKNP<NetIO> * ot_sender, *ot_receiver;

        // paillier encryption tools
        std::unique_ptr<PrivatePaillier> sk;
        std::unique_ptr<PublicPaillier> pk;

        // garbled circuit inputs inputs and output
        std::vector<BigNum> gc_x, gc_y;
        std::vector<BigNum> gc_z;

        int gc_party;

        std::vector<uint64_t> comm_, comm_gc;

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

            if (params->start_size > 0) {
                auto status = CreateMockTrees(params->start_size);
                if (!status.ok()) {
                    std::cerr << status << std::endl;
                    std::runtime_error("[Party] failure in creating mock trees");
                }
            }
        }

        Status CreateMockTrees(size_t size) {
            std::cout << "[Party] creating mock plaintext tree..." << std::flush;
            // fill plaintext tree with random elements
            std::vector<ElementAndPayload> elements;
            for (size_t i = 0; i < size; i++) {
                elements.push_back(
                    std::make_pair(
                        this->ctx_->CreateBigNum(std::stoull(GetRandomSetElement())),
                        this->ctx_->One()
                    )
                );
            }

            std::vector<std::string> hashes;
            this->my_tree.insert(elements, hashes);
            std::cout << " done" << std::endl;

            std::cout << "[Party] creating mock encrypted tree..." << std::flush;
            // fill encrypted tree with encryptions of zero
            ASSIGN_OR_RETURN(BigNum zero, this->pk->Encrypt(ctx_->Zero()));
            this->other_tree.crypto_tree.clear();
            this->other_tree.depth = this->my_tree.depth;
            this->other_tree.actual_size = this->my_tree.actual_size;
            for (const CryptoNode<ElementAndPayload>& pnode : this->my_tree.crypto_tree) {
                CryptoNode<PaillierPair> enode(pnode.node_size);
                for (size_t i = 0; i < pnode.node_size; i++) {
                    PaillierPair pair(zero, zero);
                    enode.node.push_back(pair);
                }
                this->other_tree.crypto_tree.push_back(std::move(enode));
            }
            std::cout << " done" << std::endl;
            return OkStatus();
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


        void GarbledCircuitIOSetup(emp::NetIO* io) {this->gc_io_ = io;}
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

            for (const PaillierPair& path_i: path) {
                BigNum alpha = this->ctx_->GenerateRandLessThan(this->pk->n());
                gc_x.push_back(alpha);

                ASSIGN_OR_RETURN(BigNum alpha_minus_x, this->pk->Encrypt(alpha - element.first)); //alpha >> element
                BigNum tmp = this->pk->Add(alpha_minus_x, path_i.first);//y - x + alpha

                if(element.second != this->ctx_->One()) {
                    BigNum p_times_q = this->pk->Multiply(path_i.second, value);
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
                ASSIGN_OR_RETURN(BigNum tmp, this->sk->Decrypt(elements_i));
                gc_y.push_back(tmp);
            }

            return OkStatus();
        }

        StatusOr<uint64_t> GarbledCircuit(bool is_sender) {
            int cnt;
            if(is_sender) cnt = gc_x.size();
            else cnt = gc_y.size();

            std::vector<bool> my_bit;

            bool bool_val[GC_SIZE];
            emp::Integer a[cnt], b[cnt];
            for (int i = 0; i < cnt; ++i) {
                if(is_sender) BigNum2bool(gc_x[i], bool_val);
                else BigNum2bool(gc_y[i], bool_val);
                a[i].init(bool_val, GC_SIZE, emp::ALICE);
                b[i].init(bool_val, GC_SIZE, emp::BOB);
			}
			emp::Bit eq_vct[cnt];
			for (int i = 0; i < cnt; ++i) {
                Bit eq(true);
                bool cur_bit = 0;
                if(gc_party == emp::ALICE) {
                	cur_bit = rand() & 1;
                	my_bit.push_back(cur_bit);
                }
                emp::Bit tmp(cur_bit ^ 1, emp::ALICE);

                eq = (a[i] == b[i]);
                //if(eq.reveal()) std::cerr<<"# " << i << "\n";
                eq = eq ^ tmp;
                
                eq_vct[i] = eq;
            }
            
            for (int i = 0; i < cnt; ++i) {
            	bool cur_bit = 0;
                if(gc_party == emp::ALICE) eq_vct[i].reveal(emp::BOB);
                else cur_bit = eq_vct[i].reveal(emp::BOB);

                if(gc_party == emp::BOB) my_bit.push_back(cur_bit);
            }

            BigNum rs = ctx_->Zero();

            int len = 0, cnt_block = 0;
            BigNum cur_n = ctx_->Zero();
            if(is_sender) cur_n = this->pk->n();
            else cur_n = this->sk->n();

            len = cur_n.ToBytes().length();

            cnt_block = (len * 2 + 15) >> 4; // ceil(len*2/16)

            bool chosen_bit[cnt_block * cnt];

            emp::block block_zero[cnt_block * cnt];
            emp::block block_one[cnt_block * cnt];

            //std::cerr << cnt_block << " " << cnt << std::endl;
            for (int i = 0; i < cnt; ++i) {
                if(is_sender) {
                    BigNum beta = this->ctx_->GenerateRandLessThan(cur_n);
                    ASSIGN_OR_RETURN(BigNum encrypted_beta, this->pk->Encrypt(cur_n - beta));
                    BigNum if_eq = this->pk->Add(gc_z[i], encrypted_beta);
                    BigNum if_neq = encrypted_beta;
					
					if(my_bit[i] == 0) {
		                BigNum2block(if_eq, &block_zero[cnt_block * i], cnt_block);
		                BigNum2block(if_neq, &block_one[cnt_block * i], cnt_block);
		            }
		            else {
		                BigNum2block(if_eq, &block_one[cnt_block * i], cnt_block);
		                BigNum2block(if_neq, &block_zero[cnt_block * i], cnt_block);
		            }

                    rs = rs + beta;
                }
                else {
                	for (int j = 0; j < cnt_block; ++j) chosen_bit[i * cnt_block + j] = my_bit[i];
                }
            }
            
            if(is_sender) ot_sender->send(block_zero, block_one, cnt_block * cnt);
            else {
            	ot_receiver->recv(block_zero, chosen_bit, cnt_block * cnt);
            	
				for (int i = 0; i < cnt; ++i) {
                    ASSIGN_OR_RETURN(BigNum tmp, this->sk->Decrypt(block2BigNum(&block_zero[cnt_block * i], cnt_block, ctx_)));
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
            //std::cerr<<(long long)rs_<<std::endl;

            return rs_;
        }

        StatusOr<uint64_t> GarbledCircuit() {
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
};

} // namespace deletion
} // namespace upsi
