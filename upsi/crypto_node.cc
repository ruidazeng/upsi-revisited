#include "upsi/util/elgamal_proto_util.h"
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

////////////////////////////////////////////////////////////////////////////////
// CRYPTONODE::PAD()
////////////////////////////////////////////////////////////////////////////////
template<>
void CryptoNode<Element>::pad(Context* ctx) {
    while (node.size() < node_size) {
        node.push_back(GetRandomPadElement(ctx));
    }
}

template<>
void CryptoNode<ElementAndPayload>::pad(Context* ctx) {
    while (node.size() < node_size) {
        node.push_back(std::make_pair(GetRandomPadElement(ctx), ctx->Zero()));
    }
}

template<>
void CryptoNode<Ciphertext>::pad(Context* ctx) {
    throw std::runtime_error("not implemented (yet)");
}

template<>
void CryptoNode<CiphertextAndPayload>::pad(Context* ctx) {
    throw std::runtime_error("not implemented (yet)");
}

////////////////////////////////////////////////////////////////////////////////
// CRYPTONODE::ENCRYPT()
////////////////////////////////////////////////////////////////////////////////
StatusOr<CryptoNode<Ciphertext>> EncryptNode(
    Context* ctx,
    ElGamalEncrypter* encrypter,
    const CryptoNode<Element>& node
) {
    CryptoNode<Ciphertext> encrypted(node.node_size);
    for (size_t i = 0; i < node.node.size(); i++) {
        ASSIGN_OR_RETURN(Ciphertext ciphertext, encrypter->Encrypt(node.node[i]));
        encrypted.addElement(ciphertext);
    }
    return encrypted;
}

StatusOr<CryptoNode<CiphertextAndPayload>> EncryptNode(
    Context* ctx,
    ElGamalEncrypter* elgamal,
    ThresholdPaillier* paillier,
    const CryptoNode<ElementAndPayload>& node
) {
    CryptoNode<CiphertextAndPayload> encrypted(node.node_size);
    for (size_t i = 0; i < node.node.size(); i++) {
        ASSIGN_OR_RETURN(Ciphertext ciphertext, elgamal->Encrypt(std::get<0>(node.node[i])));
        ASSIGN_OR_RETURN(BigNum payload, paillier->Encrypt(std::get<1>(node.node[i])));
        CiphertextAndPayload pair = std::make_pair(std::move(ciphertext), std::move(payload));
        encrypted.addElement(pair);
    }
    return encrypted;
}

////////////////////////////////////////////////////////////////////////////////
// CRYPTONODE::SERIALIZE()
////////////////////////////////////////////////////////////////////////////////
template<>
Status CryptoNode<Element>::serialize(TreeNode* obj) {
    throw std::runtime_error("[CryptoNode<Element>] not implemented");
}

template<>
Status CryptoNode<ElementAndPayload>::serialize(TreeNode* obj) {
    throw std::runtime_error("[CryptoNode<ElementAndPayload>] not implemented");
}

template<>
Status CryptoNode<Ciphertext>::serialize(TreeNode* obj) {
    for (const Ciphertext& elem : node) {
        EncryptedElement* ee = obj->add_elements();
        ASSIGN_OR_RETURN(
            *ee->mutable_element(), 
            elgamal_proto_util::SerializeCiphertext(elem)
        );
    }
    return OkStatus();
}

template<>
Status CryptoNode<CiphertextAndPayload>::serialize(TreeNode* obj) {
    for (const CiphertextAndPayload& elem : node) {
        EncryptedElement* ee = obj->add_elements();
        ASSIGN_OR_RETURN(
            *ee->mutable_element(), 
            elgamal_proto_util::SerializeCiphertext(std::get<0>(elem))
        );

        *ee->mutable_payload() = std::get<1>(elem).ToBytes();
    }
    return OkStatus();
}

template class CryptoNode<Element>;
template class CryptoNode<Ciphertext>;
template class CryptoNode<ElementAndPayload>;
template class CryptoNode<CiphertextAndPayload>;

} // namespace upsi
