#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "upsi/crypto/context.h"
#include "upsi/crypto/ec_commutative_cipher.h"
#include "upsi/crypto/elgamal.h"
#include "upsi/crypto/paillier.h"
#include "upsi/crypto/threshold_paillier.h"
#include "upsi/crypto_tree.h"
#include "upsi/data_util.h"
#include "upsi/message_sink.h"
#include "upsi/protocol_client.h"
#include "upsi/upsi.pb.h"
#include "upsi/util/status.inc"
#include "upsi/utils.h"

using namespace upsi;

Status run() {
  Context context;
  ASSIGN_OR_RETURN(ECGroup group, ECGroup::Create(curve_id, &context));
  ASSIGN_OR_RETURN(auto key_pair0, elgamal::GenerateKeyPair(group));
  ASSIGN_OR_RETURN(auto key_pair1, elgamal::GenerateKeyPair(group));
  std::vector<std::unique_ptr<elgamal::PublicKey>> shares;
  shares.push_back(std::move(key_pair0.first));
  shares.push_back(std::move(key_pair1.first));
  ASSIGN_OR_RETURN(auto shared_pub, elgamal::GeneratePublicKeyFromShares(shares));
  
  auto encrypter = ElGamalEncrypter(&group, std::move(shared_pub));
  
  auto decrypter0 = ElGamalDecrypter(&group, std::move(key_pair0.second));
  auto decyrpter1 = ElGamalDecrypter(&group, std::move(key_pair1.second));
  
  int num = rand() % 100;
  ASSIGN_OR_RETURN(auto x, encrypter.Encrypt(context.CreateBigNum(num)));
  ASSIGN_OR_RETURN(auto y, encrypter.Encrypt(context.CreateBigNum(num)));
  ASSIGN_OR_RETURN(Ciphertext minus_x, elgamal::Invert(x));
  ASSIGN_OR_RETURN(Ciphertext y_minus_x, elgamal::Mul(y, minus_x));
  
  BigNum mask = encrypte.CreateRandomMask();
  
  
  
}


int main() {
    run();
	return 0;
}
