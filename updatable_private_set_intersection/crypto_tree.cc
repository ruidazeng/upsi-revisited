#include "updatable_private_set_intersection/utils.h"
#include "updatable_private_set_intersection/crypto_tree.h"
#include "updatable_private_set_intersection/crypto_node.h"


/// @brief Tree Construction

namespace updatable_private_set_intersection {

template<typename T> 
CryptoTree<T>::CryptoTree() {};

template<typename T> 
CryptoTree<T>::CryptoTree(int stash_size, int node_size) {
    this->node_size = node_size;
    this->stash_size = stash_size;
    
    // Index for root node is 1, index for stash node is 0
    CryptoNode<T> stash = CryptoNode<T>(stash_size);
    CryptoNode<T> root = CryptoNode<T>(node_size);

    // depth = 0
    this->crypto_tree.push_back(stash);
    this->crypto_tree.push_back(root);
    
}

template<typename T> 
int CryptoTree<T>::getDepth() {
    return this->depth;
}

template<typename T> 
int CryptoTree<T>::getNodeSize() {
    return this->node_size;
}

template<typename T> 
int CryptoTree<T>::getStashSize() {
    return this->stash_size;
}

template<typename T> 
std::vector<CryptoNode<T> > CryptoTree<T>::getTree() {
	return this->crypto_tree;
}

/// @brief Helper methods
template<typename T> 
void CryptoTree<T>::addNewLayer() {
    this->depth += 1;
    int new_size = (1 << (this->depth + 1));
    this->crypto_tree.resize(new_size);
}



// compute leaf index of a binary hash
template<typename T> 
int CryptoTree<T>::computeIndex(BinaryHash binary_hash) {
	int x = 1;
	for (int i = 0; i < this->depth; ++i) {
        if (binary_hash[i] == '0') x = (x << 1);
        else if (binary_hash[i] == '1') x = ((x << 1) | 1);
    }
    return x;
}

// Return indices in paths in decreasing order (including stash)
template<typename T> 
void CryptoTree<T>::extractPathIndices(int* leaf_ind, int leaf_cnt, std::vector<int> &ind) {
	assert(ind.size() == 0);
	
	// add the indicies of leaves
	for (int i = 0; i < leaf_cnt; ++i) 
		ind.push_back(leaf_ind[i]);
		
	// erase duplicates and sort in decreasing order
	std::sort(ind.begin(), ind.end(), std::greater<int>());
	ind.erase(std::unique(ind.begin(), ind.end()), ind.end());
	
	int node_cnt = ind.size();
	for (int i = 0; i < node_cnt; ++i) {
		if(ind[i] == 0) break; // stash
		int tmp = (ind[i] >> 1); // find its parent 
		assert(ind[node_cnt - 1] >= tmp);
		if(ind[node_cnt - 1] > tmp) {
			ind.push_back(tmp);
			++node_cnt;
		}
	}
}

// Generate random paths, return the indices of leaves and nodes(including stash)
template<typename T> 
int* CryptoTree<T>::generateRandomPaths(int cnt, std::vector<int> &ind, std::vector<BinaryHash> &hsh) { //ind: node indices
	
	// compute leaf indices of the paths
	int *leaf_ind = new int[cnt];
	for (int i = 0; i < cnt; ++i) leaf_ind[i] = computeIndex(hsh[i]);
	
	// extract indices of nodes in these paths (including stash)
	extractPathIndices(leaf_ind, cnt, ind);
	
	return leaf_ind;
	// the sender requires indices of leaves if update one path at a time
	// need to delete leaf_ind outside this function
}


// @brief Real methods

// Insert new set elements (sender)
// Return vector of (plaintext) nodes
// stash: index = 0
template<typename T> 
std::vector<CryptoNode<T> > CryptoTree<T>::insert(std::vector<T> elem, std::vector<BinaryHash> &hsh) {
	int new_elem_cnt = elem.size();
	
	// add new layer when tree is full
	while(new_elem_cnt + this->actual_size >= (1 << (this->depth + 1))) addNewLayer();
	// no need to tell the receiver the new depth of tree?
	
	// get the node indices in random paths
	std::vector<int> ind;
	// generate binary hash
	generateRandomHash(new_elem_cnt, hsh);
	int *leaf_ind = generateRandomPaths(new_elem_cnt, ind, hsh); 
	
	/*
		To compute lca of x , y:
		let t be the leftmost 1 of (x xor y), steps = log2(t) + 1
		lca = x / 2t = x >> steps
	*/
	for (int o = 0; o < new_elem_cnt; ++o) {
		// extract all elements in the path and empty the origin node
		std::vector<T> tmp_elem[this->depth + 2];
		
		for (int u = leaf_ind[o]; ; u >>= 1) {
		
			std::vector<T> tmp_node = crypto_tree[u].getNode();
			if(u == 0) tmp_node.push_back(elem[o]);
			
			for (auto it = tmp_node.begin(); it != tmp_node.end(); ++it) {
				int x = computeIndex( computeBinaryHash(*it) );
				int steps = 0;
				if(x != leaf_ind[o]) steps = 32 - __builtin_clz(x ^ leaf_ind[o]);
				tmp_elem[steps].push_back(*it);
			}
			
			crypto_tree[u].clear();
			if(u == 0) break;
		}
		
		//fill the path
		int st = 0;
		for (int u = leaf_ind[o], steps = 0; ; u >>= 1, ++steps) {
			while(st <= steps && tmp_elem[st].empty()) ++st;
			while(st <= steps) {
				T cur_elem = tmp_elem[st].back();
				if(crypto_tree[u].addElement(cur_elem)) tmp_elem[st].pop_back();
				else break;
				while(st <= steps && tmp_elem[st].empty()) ++st;
			}
			if(u == 0) break;
		}
		assert(st > this->depth);
	}
	
	delete [] leaf_ind;
	
	// update actual_size
	this->actual_size += new_elem_cnt;
	
	int node_cnt = ind.size();
	std::vector<CryptoNode<T> > rs;
	for (int i = 0; i < node_cnt; ++i) rs.push_back(crypto_tree[ind[i]]);
	return rs;
}

// Update tree (receiver)
template<typename T> 
void CryptoTree<T>::replaceNodes(int new_elem_cnt, std::vector<CryptoNode<T> > new_nodes, std::vector<BinaryHash> &hsh) {
	
	int node_cnt = new_nodes.size();
	
	// add new layer when tree is full
	while(new_elem_cnt + this->actual_size >= (1 << (this->depth + 1))) addNewLayer();

	std::vector<int> ind;
	int *leaf_ind = generateRandomPaths(new_elem_cnt, ind, hsh);
	delete [] leaf_ind;
	
	assert(node_cnt == ind.size());
	
	// replace nodes (including stash)
	for (int i = 0; i < node_cnt; ++i) crypto_tree[ind[i]] = new_nodes[i];
	
	// update actual_size
	this->actual_size += new_elem_cnt;
}


// Find path for an element (including stash) and extract all elements on the path
template<typename T> 
std::vector<T> CryptoTree<T>::getPath(std::string element) {
    std::vector<T> encyrpted_elem;
    BinaryHash binary_hash = computeBinaryHash(element);
    int leaf_index = computeIndex(binary_hash);

	for (int u = leaf_index; ; u >>= 1) {
		this->crypto_tree[u].copyElementsTo(encyrpted_elem);
		if (u == 0) break;
	}
    return encyrpted_elem;
}

template class CryptoTree<std::string>;
template class CryptoTree<elgamal::Ciphertext>;

} // namespace updatable_private_set_intersection
