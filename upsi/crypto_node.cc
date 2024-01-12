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
void CryptoNode<ElementAndPayload>::pad(Context* ctx) {
    while (node.size() < node_size) {
        node.push_back(std::make_pair(GetRandomPadElement(ctx), ctx->Zero()));
    }
}


////////////////////////////////////////////////////////////////////////////////
// ENCRYPT NODE
////////////////////////////////////////////////////////////////////////////////


StatusOr<CryptoNode<CiphertextAndPayload>> EncryptNode(
    Context* ctx,
    PrivatePaillier* paillier,
    const CryptoNode<ElementAndPayload>& node
) {
    CryptoNode<CiphertextAndPayload> encrypted(node.node_size);
    for (size_t i = 0; i < node.node.size(); i++) {
        ASSIGN_OR_RETURN(BigNum element, paillier->Encrypt(std::get<0>(node.node[i])));
        BigNum value = std::get<1>(node.node[i]);
        if(!value.IsNonNegative()) value = paillier->n() + value;
        ASSIGN_OR_RETURN(BigNum payload, paillier->Encrypt(value));
        CiphertextAndPayload pair = std::make_pair(std::move(element), std::move(payload));
        encrypted.addElement(pair);
    }
    return encrypted;
}

////////////////////////////////////////////////////////////////////////////////
// CRYPTONODE::SERIALIZE()
////////////////////////////////////////////////////////////////////////////////

template<>
Status CryptoNode<CiphertextAndPayload>::serialize(TreeNode* obj) {
    for (const CiphertextAndPayload& elem : node) {
        EncryptedElement* ee = obj->add_elements();
        *ee->mutable_element() = std::get<0>(elem).ToBytes();
        *ee->mutable_payload() = std::get<1>(elem).ToBytes();
    }
    return OkStatus();
}

template class CryptoNode<ElementAndPayload>;
//template class CryptoNode<CiphertextAndPayload>;

} // namespace upsi
