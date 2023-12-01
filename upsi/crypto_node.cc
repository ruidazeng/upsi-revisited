#include "upsi/crypto_node.h"

namespace upsi {

/* Default constructor
template<typename T>
CryptoNode<T>::CryptoNode() {};
*/
// Initialize CryptoNode with node size
template<typename T>
CryptoNode<T>::CryptoNode(size_t node_size) {
    this->node_size = node_size;
}

/* Get node size
template<typename T>
int CryptoNode<T>::getNodeSize() {
    return this->node_size;
}*/

/* Get the node vector
template<typename T>
std::vector<T> CryptoNode<T>::getNode() {
    return this->node;
}
*/

template<typename T>
void CryptoNode<T>::clear() {
    node.clear();
}

template<typename T>
CryptoNode<T> CryptoNode<T>::copy() {
    CryptoNode<T> copy(this->node_size);
    copyElementsTo(copy.node);
    return copy;
}

template<typename T>
void CryptoNode<T>::copyElementsTo(std::vector<T> &elem) {
	int now_cnt = this->node.size();
	for (int i = 0; i < now_cnt; ++i) {
		elem.push_back(elementCopy(this->node[i]));
	}
	//elem.insert(elem.end(), node.begin(), node.end());
}

// Add an element to the node vector, return true if success, false if it's already full
template<typename T>
bool CryptoNode<T>::addElement(T &elem) {
    size_t node_vec_size = this->node.size();
    if (node_vec_size >= this->node_size) {
        return false;
    }
    else {
        this->node.push_back(std::move(elementCopy(elem)));
        return true;
    }
}


// TODO: do we want padding elements to be distinct from real ones?
template<>
void CryptoNode<std::string>::pad() {
    while (node.size() < node_size) {
        node.push_back(GetRandomNumericString(32));
    }
}

template<>
void CryptoNode<elgamal::Ciphertext>::pad() {
    throw std::runtime_error("not implemented (yet)");
}

template<>
StatusOr<CryptoNode<elgamal::Ciphertext>> CryptoNode<std::string>::encrypt(
    Context* ctx,
    ElGamalEncrypter* encrypter
) {
    CryptoNode<elgamal::Ciphertext> encrypted(node_size);
    for (size_t i = 0; i < node.size(); i++) {
        BigNum elem = ctx->CreateBigNum(NumericString2uint(node[i]));
        ASSIGN_OR_RETURN(Ciphertext ciphertext, encrypter->Encrypt(elem));
        encrypted.addElement(ciphertext);
    }
    return encrypted;
}

template<>
StatusOr<CryptoNode<elgamal::Ciphertext>> CryptoNode<elgamal::Ciphertext>::encrypt(
    Context* ctx,
    ElGamalEncrypter* encrypter
) {
    throw std::runtime_error("[CryptoNode] trying to encrypt an encrypted node");
}

template<>
Status CryptoNode<std::string>::serialize(OneNode* obj) {
    throw std::runtime_error("[CryptoNode] not implemented");
}

template<>
Status CryptoNode<elgamal::Ciphertext>::serialize(OneNode* onenode) {
    for (const elgamal::Ciphertext& elem : node) {
        EncryptedElement* ee = onenode->add_elements();
        ASSIGN_OR_RETURN(*ee->mutable_elgamal_u(), elem.u.ToBytesCompressed());
        ASSIGN_OR_RETURN(*ee->mutable_elgamal_e(), elem.e.ToBytesCompressed());
    }
    return OkStatus();
}

template class CryptoNode<std::string>;
template class CryptoNode<elgamal::Ciphertext>;

} // namespace upsi
