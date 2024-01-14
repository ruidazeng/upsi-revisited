#include "upsi/crypto_tree.h"

#include "upsi/util/elgamal_proto_util.h"


/// @brief Tree Construction

namespace upsi {
/*
template<typename T>
BaseTree<T>::BaseTree() {};
*/
template<typename T>
BaseTree<T>::BaseTree(int stash_size, size_t node_size) {
    this->node_size = node_size;
    this->stash_size = stash_size;

    // Index for root node is 1, index for stash node is 0
    CryptoNode<T> stash = CryptoNode<T>(stash_size);
    CryptoNode<T> root = CryptoNode<T>(node_size);

    // depth = 0
    this->crypto_tree.push_back(std::move(stash));
    this->crypto_tree.push_back(std::move(root));

}

/// @brief Helper methods
template<typename T>
void BaseTree<T>::addNewLayer() {
    this->depth += 1;
    int new_size = (1 << (this->depth + 1));
    this->crypto_tree.resize(new_size);
}



// compute leaf index of a binary hash
template<typename T>
int BaseTree<T>::computeIndex(BinaryHash binary_hash) {
	//std::cerr << this->depth << std::endl;
	int x = 1;
	for (int i = 0; i < this->depth; ++i) {
        if (binary_hash[i] == '0') x = (x << 1);
        else if (binary_hash[i] == '1') x = ((x << 1) | 1);
    }
    return x;
}

// Return indices in paths in decreasing order (including stash)
template<typename T>
void BaseTree<T>::extractPathIndices(int* leaf_ind, int leaf_cnt, std::vector<int> &ind) {
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
int* BaseTree<T>::generateRandomPaths(int cnt, std::vector<int> &ind, std::vector<BinaryHash> &hsh) { //ind: node indices

	// compute leaf indices of the paths
	int *leaf_ind = new int[cnt];
	for (int i = 0; i < cnt; ++i) leaf_ind[i] = computeIndex(Byte2Binary(hsh[i]));

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
std::vector<CryptoNode<T>> BaseTree<T>::insert(
    std::vector<T> &elem,
    std::vector<std::string> &hsh
) {
	int new_elem_cnt = elem.size();

	// add new layer when tree is full
	while(new_elem_cnt + this->actual_size >= (1 << (this->depth + 1))) addNewLayer();
	// no need to tell the receiver the new depth of tree?

	// get the node indices in random paths
	std::vector<int> ind;

	// generate hash
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
		std::vector<T> unique_elem[this->depth + 2];

		//std::cerr << "************leaf ind = " << leaf_ind[o] << std::endl;
		for (int u = leaf_ind[o]; ; u >>= 1) {
			std::vector<T> tmp_node;
			crypto_tree[u].copyElementsTo(tmp_node);
			if(u == 0) tmp_node.push_back(std::move(elementCopy(elem[o])));

			int tmp_node_size = tmp_node.size();
			//std::cerr << "tmp_node size  = " << tmp_node_size << std::endl;

			for (int i = 0; i < tmp_node_size; ++i) {
				int x = computeIndex(computeBinaryHash(tmp_node[i]) );
				//if(u == 0 && i == 0) std::cerr<<"index is " << x << std::endl;
				int steps = 0;
				if(x != leaf_ind[o]) steps = 32 - __builtin_clz(x ^ leaf_ind[o]);
				tmp_elem[steps].push_back(std::move(tmp_node[i]));
				//std::cerr << "add " << x << " to " << (x >> steps) << std::endl;
			}

			crypto_tree[u].clear();
			if(u == 0) break;
		}
		
		Context ctx;
		for (int i = 0; i <= this->depth + 1; ++i) {
			std::sort(tmp_elem[i].begin(), tmp_elem[i].end());
			int cnt_vct = tmp_elem[i].size();
			for (int j = 0; j < cnt_vct; ++j) {
				BigNum cur_elem = tmp_elem[i][j].first;
				BigNum val = tmp_elem[i][j].second;
				while(j + 1 < cnt_vct && tmp_elem[i][j + 1].first == cur_elem) {
					++j;
					val += tmp_elem[i][j].second;
				}
				//val = val.Mod(my_paillier->n());
				if(val != ctx.Zero()) unique_elem[i].push_back(std::make_pair(cur_elem, val));
			}
			
		}
		
		//fill the path
		int st = 0;
		for (int u = leaf_ind[o], steps = 0; ; u >>= 1, ++steps) {
			while(st <= steps && unique_elem[st].empty()) ++st;
			while(st <= steps) {
				T cur_elem = std::move(elementCopy(unique_elem[st].back()));
				if(crypto_tree[u].addElement(cur_elem)) unique_elem[st].pop_back();
				else break;
				while(st <= steps && unique_elem[st].empty()) ++st;
			}
			if(u == 0) break;
		}
		assert(st > this->depth);
	}
	/*
	for (size_t i = 0; i < crypto_tree.size(); ++i) {
		std::cerr << crypto_tree[i].node.size() << " ";
	} std::cerr << std::endl;*/

	delete [] leaf_ind;

	// update actual_size
	this->actual_size += new_elem_cnt;

	int node_cnt = ind.size();
	std::vector<CryptoNode<T>> rs;
	for (int i = 0; i < node_cnt; ++i) {
        rs.push_back(crypto_tree[ind[i]].copy());
    }
	return rs;
}

// Update tree (receiver)
template<typename T>
void BaseTree<T>::replaceNodes(int new_elem_cnt, std::vector<CryptoNode<T> > &new_nodes, std::vector<std::string> &hsh) {

	int node_cnt = new_nodes.size();

	// add new layer when tree is full
	while(new_elem_cnt + this->actual_size >= (1 << (this->depth + 1))) addNewLayer();
	//std::cerr << "new depth: " << this->depth << std::endl;

	std::vector<int> ind;
	int *leaf_ind = generateRandomPaths(new_elem_cnt, ind, hsh);
	delete [] leaf_ind;

	assert(node_cnt == ind.size());

	//for (int i = 0; i < node_cnt; ++i) std::cerr << ind[i] << std::endl;

	// replace nodes (including stash)
	for (int i = 0; i < node_cnt; ++i) crypto_tree[ind[i]] = std::move(new_nodes[i]);

	// update actual_size
	this->actual_size += new_elem_cnt;
}


// Find path for an element (including stash) and extract all elements on the path
template<typename T>
std::vector<T> BaseTree<T>::getPath(Element element) {
    std::vector<T> encyrpted_elem;
    //std::cerr << "computing binary hash of "<< element << "\n";
    BinaryHash binary_hash = computeBinaryHash(element);
    //std::cerr << "hash is " << binary_hash << "\n";
    //std::cerr << "computing index...\n";
    int leaf_index = computeIndex(binary_hash);
    //std::cerr << "get a path from " << leaf_index << std::endl;

	//std::cerr << "tree size = " << crypto_tree.size() << std::endl;
	for (int u = leaf_index; ; u >>= 1) {
		//if(crypto_tree[u].node.size() > 0) std::cerr<< crypto_tree[u].node.size() << " ";
		this->crypto_tree[u].copyElementsTo(encyrpted_elem);
		if (u == 0) break;
	}
    return encyrpted_elem;
}

Status CryptoTree<ElementAndPayload>::Update(
    Context* ctx,
    PrivatePaillier* paillier,
    std::vector<ElementAndPayload>& elements, 
    TreeUpdates* updates
) {
    std::vector<std::string> hashes;

    std::vector<CryptoNode<ElementAndPayload>> nodes = this->insert(elements, hashes);

    for (size_t i = 0; i < nodes.size(); i++) {
        nodes[i].pad(ctx);

        ASSIGN_OR_RETURN(
            CryptoNode<CiphertextAndPayload> ciphertext,
            EncryptNode(ctx, paillier, nodes[i])
        );

        RETURN_IF_ERROR(ciphertext.serialize(updates->add_nodes()));
    }

    for (const std::string &hash : hashes) {
        updates->add_hashes(hash);
    }

    return OkStatus();
}

Status CryptoTree<CiphertextAndPayload>::Update(
    Context* ctx,
    ECGroup* group,
    const TreeUpdates* updates
) {
    std::vector<std::string> hashes(updates->hashes().begin(), updates->hashes().end());

    std::vector<CryptoNode<CiphertextAndPayload>> new_nodes;
    for (const TreeNode& tnode : updates->nodes()) {
        auto* cnode = new CryptoNode<CiphertextAndPayload>(DEFAULT_NODE_SIZE);
        for (const EncryptedElement& element : tnode.elements()) {
            auto pair = std::make_pair(
                ctx->CreateBigNum(element.element()), ctx->CreateBigNum(element.payload())
            );
            cnode->addElement(pair);
        }
        new_nodes.push_back(std::move(*cnode));
    }
    this->replaceNodes(hashes.size(), new_nodes, hashes);

    return OkStatus();
}

//template class BaseTree<Element>;
//template class BaseTree<Ciphertext>;
template class BaseTree<ElementAndPayload>;
//template class BaseTree<CiphertextAndPayload>;

} // namespace upsi
