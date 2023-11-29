#include "upsi/crypto_node.h"

namespace upsi {

/* Default constructor
template<typename T>
CryptoNode<T>::CryptoNode() {};
*/
// Initialize CryptoNode with node size
template<typename T>
CryptoNode<T>::CryptoNode(int node_size) {
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
    CryptoNode<T> copy;
    copyElementsTo(copy.node);
    return copy;
}

template<typename T>
void CryptoNode<T>::copyElementsTo(const std::vector<T> &elem) {
	int now_cnt = elem.size();
	for (int i = 0; i < now_cnt; ++i) {
		node.push_back(std::move(elementCopy(elem[i])));
	}
	//elem.insert(elem.end(), node.begin(), node.end());
}

// Add an element to the node vector, return true if success, false if it's already full
template<typename T>
bool CryptoNode<T>::addElement(T &elem) {
    int node_vec_size = this->node.size();
    if (node_vec_size >= this->node_size) {
        return false;
    }
    else {
        this->node.push_back(std::move(elem));
        return true;
    }
}

template class CryptoNode<std::string>;
template class CryptoNode<elgamal::Ciphertext>;

} // namespace upsi
