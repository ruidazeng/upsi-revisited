# UPSI Project

## How to run the protocol

In order to run Updatable Private Set Intersection, you need to install Bazel, if you
don't have it already.
[Follow the instructions for your platform on the Bazel website.](https://docs.bazel.build/versions/master/install.html)

You also need to install Git, if you don't have it already.
[Follow the instructions for your platform on the Git website.](https://git-scm.com/book/en/v2/Getting-Started-Installing-Git)

Once you've installed Bazel and Git, open a Terminal and clone the Private Join
and Compute repository into a local folder:

```shell
git clone https://github.com/ruidazeng/upsi-googlelib.git
```

Navigate into the `private-join-and-compute` folder you just created, and build
the Private Join and Compute library and dependencies using Bazel:

```bash
cd private-join-and-compute
bazel build //updatable_private_set_intersection:all
```

## UPSI Files

updatable_private_set_intersection/crypto_node.h

updatable_private_set_intersection/crypto_node.cc

updatable_private_set_intersection/crypto_tree.h

updatable_private_set_intersection/crypto_tree.cc

updatable_private_set_intersection/protocol_party.h

updatable_private_set_intersection/protocol_party.cc

## Google Library Files (depdencies)

crypto/bignum.h

crypto/context.h

crypto/ec_commutative_cipher.h

crypto/paillier.h