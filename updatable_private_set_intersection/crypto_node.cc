#include "updatable_private_set_intersection/utils.h"
#include "updatable_private_set_intersection/crypto_node.h"

namespace updatable_private_set_intersection {

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

// Get the node vector
template<typename T> 
std::vector<T> CryptoNode<T>::getNode() {
    return this->node;
}

template<typename T> 
void CryptoNode<T>::clear() {
    node.clear();
}

template<typename T> 
void CryptoNode<T>::copyElementsTo(std::vector<T> &elem) {
	elem.insert(elem.end(), node.begin(), node.end());
}

// Add an element to the node vector, return true if success, false if it's already full
template<typename T> 
bool CryptoNode<T>::addElement(T elem) {
    int node_vec_size = this->node.size();
    if (node_vec_size >= this->node_size) {
        return false;
    }
    else {
        this->node.push_back(elem);
        return true;
    }
}

template class CryptoNode<std::string>;
template class CryptoNode<elgamal::Ciphertext>;

} // namespace updatable_private_set_intersection
