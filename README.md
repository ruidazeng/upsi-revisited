# UPSI Revisited

This is the implementation for the updatable private set intersection protocol presented in
[Updatable Private Set Intersection Revisited: Extended Functionalities, Deletion, and Worst-Case Complexity](https://eprint.iacr.org/2024/1446)
(Asiacrypt 2024).

> [!WARNING]
> This repository is a research prototype written to demonstrate protocol performance and should not be treated as
> "production ready".

## Building the Project

> [!IMPORTANT]
> The project should be built on Debian 10 (buster) to ensure dependencies will build without issue.

The [build.sh](build.sh) script will handle installation of build dependencies (namely python,
[bazel](https://bazel.build/), and [`emp-toolkit`](https://github.com/emp-toolkit)). The UPSI library can then be built
using the bazel endpoints:

```bash
# for the addition only cardinality, sum, and circuit updatable psi protocols
bazel build //upsi/addition:all

# for the addition & deletion cardinality and sum updatable psi protocols
bazel build //upsi/deletion:all

# for the addition only plain psi protocol
bazel build //upsi/original:all

# for the addition & deletion plain psi protocol
bazel build //upsi/deletion-psi:all
```

## Running the Experiments

Before running experiments, use the `setup` binary to generate encryption keys and mock input sets. By default, keys
and input sets will be put in `out/` and `data/`, respectively. Use the `--help` flag for each of the four protocols
(`addition`, `deletion`, `original`, and `deletion-psi`) `setup` scripts to see their parameters:
```bash
./bazel-bin/upsi/<protocol>/setup
```

To replicate the fourth row in Table 2 ($`N = 2^{18}`$, $`N_d = 2^6`$ running the updatable PSI addition only for
cardinality protocol $`\Pi_{\mathsf{UPSI-Add}_\mathsf{ca}}`$), we want to run the protocol on the day where the input
sets reach total cardinality of $2^{18}$ (i.e., the $\frac{2^{18}}{2^{6}} = 4096^\text{th}$ day). Rather than simulate
all 4096 days, specify the `--start_size` parameter in the `setup` binary to generate encrypted datasets that are used
as the "carry over" from the $4095^\text{th}$ to $4096^\text{th}$ day. Therefore, to set up this experiment use:
```bash
./bazel-bin/upsi/addition/setup --func=CA --days=1 --daily_size=64 --start_size=262080
```
_Note that $`262080 = 2^{18} - 2^6 = N - N_d`$; i.e., the size of the input sets at the start of the $`4096^\text{th}`$ day._

Once the encryption keys and data sets are generated, each party in the protocol can be run:
```bash
./bazel-bin/upsi/addition/run --party=1 --days=1 --func=CA
```
and
```bash
./bazel-bin/upsi/addition/run --party=0 --days=1 --func=CA
```

> [!NOTE]
> You must run `run --party=1` before `run --party=0` as the first party will wait for connections on the specified
> port.

More information for both the `setup` and `run` binaries can be found using the `--help` flag.

## Author Contact Information

Saikrishna Badrinarayanan (LinkedIn): [bsaikrishna7393 at gmail dot com](mailto:bsaikrishna7393@gmail.com)

Peihan Miao (Brown University): [peihan_miao at brown dot edu](mailto:peihan_miao@brown.edu)

Xinyi Shi (Brown University): [xinyi_shi at brown dot edu](mailto:xinyi_shi@brown.edu)

Max Tromanhauser (Brown University): [max_tromanhauser at brown dot edu](mailto:max_tromanhauser@brown.edu)

Ruida Zeng (Brown University): [ruida_zeng at brown dot edu](mailto:ruida_zeng@brown.edu)
