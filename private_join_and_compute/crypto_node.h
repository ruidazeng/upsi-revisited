#ifndef CryptoNode_H
#define CryptoNode_H

#include "private_join_and_compute/utils.hpp"

namespace private_join_and_compute {

/*
Type T can be a tuple for element and payload 
	or be one type for element only when there's no payload
*/
template<typename T>
class CryptoNode
{
    private:
        std::vector<T> node;
        int node_size;

    public:
        // Default constructor
        CryptoNode();

        // Initialize CryptoNode with node size
        CryptoNode(int node_size);

        // Get node size
        int getNodeSize();

        // Get the node vector
        std::vector<T> getNode();

        // Add an element to the node vector, return true if success, false if it's already full
        bool addElement(T elem);
};

} // namespace private_join_and_compute

#endif
