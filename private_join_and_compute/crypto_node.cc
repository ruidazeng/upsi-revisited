#include "private_join_and_compute/crypto_node.h"

namespace private_join_and_compute {

// Default constructor
template<typename T> 
CryptoNode<T>::CryptoNode() {};

// Initialize CryptoNode with node size
template<typename T> 
CryptoNode<T>::CryptoNode(int node_size) {
    this->node_size = node_size;
}

// Get node size
template<typename T> 
int CryptoNode<T>::getNodeSize() {
    return this->node_size;
}

// Get the node vector
template<typename T> 
std::vector<T> CryptoNode<T>::getNode() {
    return this->node;
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

} // namespace private_join_and_compute
