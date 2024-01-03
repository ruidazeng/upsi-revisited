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
// ENCRYPT NODE
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
// SERIALIZE NODE
////////////////////////////////////////////////////////////////////////////////

Status SerializeNode(CryptoNode<Element>* cnode, PlaintextNode* pnode) {
    pnode->set_node_size(cnode->node_size);
    for (const Element& elem : cnode->node) {
        PlaintextElement* pe = pnode->add_elements();
        *pe->mutable_element() = elem.ToBytes();
    }
    return OkStatus();
}

Status SerializeNode(CryptoNode<ElementAndPayload>* cnode, PlaintextNode* pnode) {
    pnode->set_node_size(cnode->node_size);
    for (const ElementAndPayload& elem : cnode->node) {
        PlaintextElement* pe = pnode->add_elements();
        *pe->mutable_element() = elem.first.ToBytes();
        *pe->mutable_payload() = elem.second.ToBytes();
    }
    return OkStatus();
}

Status SerializeNode(CryptoNode<Ciphertext>* cnode, TreeNode* tnode) {
    for (const Ciphertext& elem : cnode->node) {
        EncryptedElement* ee = tnode->add_elements();
        ASSIGN_OR_RETURN(
            *ee->mutable_no_payload()->mutable_element(),
            elgamal_proto_util::SerializeCiphertext(elem)
        );
    }
    return OkStatus();
}

Status SerializeNode(CryptoNode<CiphertextAndPayload>* cnode, TreeNode* tnode) {
    for (const CiphertextAndPayload& elem : cnode->node) {
        EncryptedElement* ee = tnode->add_elements();
        ASSIGN_OR_RETURN(
            *ee->mutable_paillier()->mutable_element(),
            elgamal_proto_util::SerializeCiphertext(elem.first)
        );

        *ee->mutable_paillier()->mutable_payload() = elem.second.ToBytes();
    }
    return OkStatus();
}

////////////////////////////////////////////////////////////////////////////////
// DESERIALIZE NODE
////////////////////////////////////////////////////////////////////////////////

StatusOr<CryptoNode<Element>> DeserializeNode(const PlaintextNode& pnode, Context* ctx) {
    CryptoNode<Element> node(pnode.node_size());
    for (const PlaintextElement& element : pnode.elements()) {
        Element e = ctx->CreateBigNum(element.element());
        node.addElement(e);
    }

    return node;
}

StatusOr<CryptoNode<ElementAndPayload>> DeserializeNodeWithPayload(
    const PlaintextNode& pnode, Context* ctx
) {
    CryptoNode<ElementAndPayload> node(pnode.node_size());
    for (const PlaintextElement& element : pnode.elements()) {
        ElementAndPayload pair = std::make_pair(
            ctx->CreateBigNum(element.element()),
            ctx->CreateBigNum(element.payload())
        );
        node.addElement(pair);
    }

    return node;
}

StatusOr<CryptoNode<Ciphertext>> DeserializeNode(const TreeNode& tnode, ECGroup* group) {
    CryptoNode<Ciphertext> node(tnode.elements().size());
    for (const EncryptedElement& element : tnode.elements()) {
        ElGamalCiphertext elem;
        if (element.has_no_payload()) {
            elem = element.no_payload().element();
        } else if (element.has_paillier()) {
            elem = element.paillier().element();
        } else {
            elem = element.elgamal().element();
        }
        ASSIGN_OR_RETURN(
            Ciphertext ciphertext,
            elgamal_proto_util::DeserializeCiphertext(group, elem)
        );
        node.addElement(ciphertext);
    }

    return node;
}

StatusOr<CryptoNode<CiphertextAndPayload>> DeserializeNode(
    const TreeNode& tnode, Context* ctx, ECGroup* group
) {
    CryptoNode<CiphertextAndPayload> node(tnode.elements().size());
    for (const EncryptedElement& element : tnode.elements()) {
        if (!element.has_paillier()) {
            return InvalidArgumentError("[CryptoNode] expected node to have paillier payload");
        }
        ASSIGN_OR_RETURN(
            Ciphertext ciphertext,
            elgamal_proto_util::DeserializeCiphertext(group, element.paillier().element())
        );
        auto pair = std::make_pair(
            std::move(ciphertext), ctx->CreateBigNum(element.paillier().payload())
        );
        node.addElement(pair);
    }

    return node;
}


template class CryptoNode<Element>;
template class CryptoNode<Ciphertext>;
template class CryptoNode<ElementAndPayload>;
template class CryptoNode<CiphertextAndPayload>;

} // namespace upsi
