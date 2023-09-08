# UPSI Project

In order to run Private Join and Compute, you need to install Bazel, if you don't have it already. Follow the instructions for your platform on the Bazel website.

You also need to install Git, if you don't have it already. Follow the instructions for your platform on the Git website.

Once you've installed Bazel and Git, open a Terminal and clone the Private Join and Compute repository into a local folder:

git clone https://github.com/google/private-join-and-compute.git
Navigate into the private-join-and-compute folder you just created, and build the Private Join and Compute library and dependencies using Bazel:

cd private-join-and-compute
bazel build //private_join_and_compute:all

## UPSI Files

private_join_and_compute/crypto_node.h
private_join_and_compute/crypto_node.cc
private_join_and_compute/crypto_tree.h
private_join_and_compute/crypto_tree.cc

private_join_and_compute/protocol_party.h
private_join_and_compute/protocol_party.cc

## Google Library Files (depdencies)

crypto/bignum.h
crypto/context.h
crypto/ec_commutative_cipher.h
crypto/paillier.h