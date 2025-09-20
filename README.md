<div align="center">

# UPSI Revisited

**Updatable Private Set Intersection: Extended Functionalities, Deletion, and Worst-Case Complexity**

*Saikrishna Badrinarayanan, Peihan Miao, Xinyi Shi, Max Tromanhauser, and Ruida Zeng*

<a href='https://eprint.iacr.org/2024/1446'><img src='https://img.shields.io/badge/Paper-IACR-blue'></a>
<a href='https://link.springer.com/chapter/10.1007/978-981-96-0938-3_7'><img src='https://img.shields.io/badge/Paper-Springer-lightblue'></a>
<a href='https://asiacrypt.iacr.org/2024/'><img src='https://img.shields.io/badge/Conference-Asiacrypt%202024-orange'></a>
<a href='https://asiacrypt.iacr.org/2024//program.php'><img src='https://img.shields.io/badge/Program-Asiacrypt%202024-green'></a>
<a href='https://artifacts.iacr.org/asiacrypt/2024/a12/'><img src='https://img.shields.io/badge/Artifact-Asiacrypt%202024-gold'></a>
<a href='https://www.youtube.com/watch?v=FddijxFRAeY'><img src='https://img.shields.io/badge/Presentation-YouTube-red?logo=youtube'/></a>
<a href='https://ghcr.io/ruidazeng/upsi-revisited'><img src='https://img.shields.io/badge/Docker-Package-blueviolet'></a>
<a href='https://eprint.iacr.org/2024/1446.pdf'><img src='https://img.shields.io/badge/ePrint-PDF-red'></a>

[**Overview**](#overview) | [**Building**](#building-the-project) | [**Experiments**](#running-the-experiments)
| [**Contact**](#author-contact-information) | [**License**](#license) | [**Citation**](#citation)

<a href="https://asiacrypt.iacr.org/2024/" target="_blank">
    <img src="Asiacrypt2024.jpg" alt="Asiacrypt 2024";>
</a>

</div>

---

## Overview

**UPSI Revisited** implements the *Updatable Private Set Intersection (UPSI)* protocol as detailed in our [Asiacrypt 2024 paper](https://eprint.iacr.org/2024/1446). Private Set Intersection (PSI) enables two mutually distrusting parties, each holding a private set of elements, to compute the intersection of their sets without disclosing any additional information. Building upon the foundational work presented in [PoPETS 2022](https://eprint.iacr.org/2021/1349), our UPSI Revisited project addresses several key limitations of existing UPSI protocols:

1. **Extended Functionalities:** Unlike previous protocols that support only plain PSI, our implementation includes advanced functionalities such as PSI-Cardinality and PSI-Sum. Additionally, in the addition-only setting, we present **Circuit-PSI** functionality that outputs secret shares of the intersection.
2. **Support for Deletion Operations:** Previous UPSI protocols were limited to the addition of elements to their existing sets and "weak deletions" (where parties can additionally delete their old elements every *t* days). Our work introduces the capability to arbitrarily delete elements, achieving semi-honest security in both the addition-only and addition-deletion settings.
3. **Optimized Worst-Case Complexity:** Existing addition-only protocols either require both parties to learn the output or only achieve low amortized complexity and incur linear worst-case complexity. Our protocols ensure that both computation and communication complexities scale solely with the size of set updates rather than the entire sets (except for a polylogarithmic factor).

**Practical Performance:** We have implemented our UPSI protocols and benchmarked them against state-of-the-art PSI and extended functionality protocols. Our results demonstrate favorable performance, particularly when dealing with sufficiently large total set sizes, sufficiently small new updates, or operating within low-bandwidth network environments.

> [!WARNING]
> This repository is a research prototype written to demonstrate our UPSI protocol's performance and to showcase its capabilities. It is **NOT** intended to be considered as "production ready" and should only be used for experimental or research & development purposes.

## Building the Project

### Container Setup with Docker

The repository has been containerized using Docker. To pull the appropriate container:
```bash
docker pull ghcr.io/ruidazeng/upsi-revisited:latest
```

#### Standard Environments
If you're using a standard environment (e.g. `amd64` Intel-based systems), run:

```bash
docker run -it ghcr.io/ruidazeng/upsi-revisited:latest
```

> [!WARNING]
> If you run into an error `RTNETLINK answers: Operation not permitted`, add `--cap-add=NET_ADMIN` to the `docker run` command.


#### Running the Container on Apple Silicon Macs or ARM Architectures

For users operating on Apple Silicon Macs (`arm64`) or other ARM-based architectures, it might be necessary to specify the platform explicitly to direct Docker to emulate the standard environments and architectures, ensure compatibility and allowing the container to run:

```bash
docker run --platform linux/amd64 -it ghcr.io/ruidazeng/upsi-revisited:latest
```

Once inside the container, you can run any of the commands outlined in the following sections.

### Building Locally

If you don't want to use Docker, you can build the project yourself.

> [!IMPORTANT]
> The project should be built on Debian 10 (buster) to ensure dependencies will build without issue.

The [build.sh](build.sh) script will handle installation of build dependencies (namely python, [bazel](https://bazel.build/), and [`emp-toolkit`](https://github.com/emp-toolkit)). The UPSI library can then be built using the bazel endpoints:

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

Before running experiments, use the `setup` binary to generate encryption keys and mock input sets. By default, keys and input sets will be placed in `out/` and `data/`, respectively.

### Protocol Descriptions
The protocols correspond to specific functionalities as outlined in the paper:
- **`addition`:** Addition-Only UPSI-Cardinality/Sum/Circuit-PSI
- **`deletion`:** UPSI-Cardinality/Sum with Addition and Deletion
- **`original`:** Addition-Only Plain UPSI
- **`deletion-psi`:** Plain UPSI with Addition and Deletion

For more details, refer to the corresponding sections in the paper:
- **`addition` & `original`:** [Section 3.2](https://eprint.iacr.org/2024/1446.pdf#page=10)
- **`deletion` & `deletion-psi`:** [Section 4.2](https://eprint.iacr.org/2024/1446.pdf#page=16)

To explore the parameters for each protocol, use the `--help` flag for the `setup` binary as follows:

```bash
./bazel-bin/upsi/<protocol>/setup --help
```

The `--func` flag specifies the functionality to be used in the experiment. The available values are:

- **`PSI`:** Plain PSI, allowing two parties to compute the intersection of their sets without revealing any additional information.

- **`CA`:** PSI-Cardinality, which computes the size of the intersection between the two sets.

- **`SUM`:** PSI-Sum, calculating the sum of values associated with the elements in the intersection.

- **`SS`:** Circuit-PSI, outputting the ***secret shares (SS)*** of the intersection.

To replicate the fourth row in Table 2 ($`N = 2^{18}`$, $`N_d = 2^6`$ running the updatable PSI addition only for cardinality protocol $`\Pi_{\mathsf{UPSI-Add}_\mathsf{ca}}`$), we want to run the protocol on the day where the input sets reach total cardinality of $2^{18}$ (i.e., the $\frac{2^{18}}{2^{6}} = 4096^\text{th}$ day). Rather than simulate all 4096 days, specify the `--start_size` parameter in the `setup` binary to generate encrypted datasets that are used as the "carry over" from the $4095^\text{th}$ to $4096^\text{th}$ day. Therefore, to set up this experiment use:
```bash
./bazel-bin/upsi/addition/setup --func=CA --days=1 --daily_size=64 --start_size=262080
```
_Note that $`262080 = 2^{18} - 2^6 = N - N_d`$; i.e., the size of the input sets at the start of the $`4096^\text{th}`$ day._

### Configuring Network Bandwidth and Latency for Experiments

To simplify the setup of network conditions for experiments, the [network_setup.sh](network_setup.sh) script is provided in the base directory. This script automates the configuration of network bandwidth and latency, simulating both LAN and WAN environments as described in [Section 6.1](https://eprint.iacr.org/2024/1446.pdf/#page=21) of the paper.

#### Overview of Network Simulations

In **Section 6.1**, the paper explains the network conditions used for experiments:
- **LAN Connection:**
  - **RTT (Round Trip Time):** 0.2 ms
  - **Bandwidth:** 1 Gbps
- **WAN Connection:**
  - **RTT (Round Trip Time):** 80 ms
  - **Bandwidth Options:** 200 Mbps, 50 Mbps, and 5 Mbps

These settings follow the same settings as previous works and are critical for reproducing the results in Tables 2, 3, 4, and 5.

#### Usage of `network_setup.sh`

1. **Enable a Specific Network Setting:**
   Use the following command to set up a specific network condition. Replace `<latency>` with the RTT latency in milliseconds and `<bandwidth>` with the desired (optional) max bandwidth in Mbps.

   ```bash
   ./network_setup.sh on <latency> <bandwidth>
   ```

   Example configurations:
   - **LAN (1 Gbps, 0.2 ms RTT):**
     ```bash
     ./network_setup.sh on 0.1 1000
     ```

   - **WAN (200 Mbps, 80 ms RTT):**
     ```bash
     ./network_setup.sh on 40 200
     ```

   - **WAN (50 Mbps, 80 ms RTT):**
     ```bash
     ./network_setup.sh on 40 50
     ```

   - **WAN (5 Mbps, 80 ms RTT):**
     ```bash
     ./network_setup.sh on 40 5
     ```

2. **Disable Network Emulation:**
   After completing the experiments under the specified network condition, disable the network emulation by running:

   ```bash
   ./network_setup.sh off
   ```

#### Example Workflow for Experiments

Once the encryption keys and data sets are generated, and the network is setup as desired, each party in the protocol can be run:
```bash
./bazel-bin/upsi/addition/run --party=1 --days=1 --func=CA
```
and
```bash
./bazel-bin/upsi/addition/run --party=0 --days=1 --func=CA
```

> [!NOTE]
> You must run `run --party=1` before `run --party=0` as the first party will wait for connections on the specified port.

Or to run both parties, you can do:
```bash
./bazel-bin/upsi/addition/run --party=1 --days=1 --func=CA & ./bazel-bin/upsi/addition/run --party=0 --days=1 --func=CA
```

> [!IMPORTANT]
> If you've used `--start_size` in the `setup` command, you must include the
> `--trees` flag in `run` to read and use the prepared state.

Below is a step-by-step example workflow to configure and run experiments under LAN and WAN conditions:

1. **Run the Experiment on LAN (1 Gbps):**
   ```bash
   ./network_setup.sh on 0.1 1000
   ./bazel-bin/upsi/addition/run --party=1 --days=1 --func=CA
   ./bazel-bin/upsi/addition/run --party=0 --days=1 --func=CA
   ./network_setup.sh off
   ```

2. **Run the Experiment on WAN (200 Mbps):**
   ```bash
   ./network_setup.sh on 40 200
   ./bazel-bin/upsi/addition/run --party=1 --days=1 --func=CA
   ./bazel-bin/upsi/addition/run --party=0 --days=1 --func=CA
   ./network_setup.sh off
   ```

3. **Run the Experiment on WAN (50 Mbps):**
   ```bash
   ./network_setup.sh on 40 50
   ./bazel-bin/upsi/addition/run --party=1 --days=1 --func=CA
   ./bazel-bin/upsi/addition/run --party=0 --days=1 --func=CA
   ./network_setup.sh off
   ```

4. **Run the Experiment on WAN (5 Mbps):**
   ```bash
   ./network_setup.sh on 40 5
   ./bazel-bin/upsi/addition/run --party=1 --days=1 --func=CA
   ./bazel-bin/upsi/addition/run --party=0 --days=1 --func=CA
   ./network_setup.sh off
   ```

More information for both the `setup` and `run` binaries can be found using the `--help` flag.

## Author Contact Information

Feel free to reach out to the authors for further inquiries or collaborations:

| Name                  | Affiliation       | Contact                              |
|-----------------------|-------------------|--------------------------------------|
| **Saikrishna Badrinarayanan** | LinkedIn  | `bsaikrishna7393 [at] gmail [dot] com` |
| **Peihan Miao**       | Brown University  | `peihan_miao [at] brown [dot] edu`  |
| **Xinyi Shi**         | Brown University  | `xinyi_shi [at] brown [dot] edu`    |
| **Max Tromanhauser**  | Brown University  | `max_tromanhauser [at] brown [dot] edu` |
| **Ruida Zeng**        | Brown University  | `ruida_zeng [at] brown [dot] edu`   |

## License

This project is licensed under the [Apache License 2.0](LICENSE).

## Citation

If you find our work useful in your research or reference it in your publications, please consider citing it as follows:

```bibtex
@inproceedings{bmxtz2024upsi,
  title="Updatable Private Set Intersection Revisited: Extended Functionalities, Deletion, and Worst-Case Complexity",
  author="Saikrishna Badrinarayanan and Peihan Miao and Xinyi Shi and Max Tromanhauser and Ruida Zeng",
  booktitle="Advances in Cryptology -- ASIACRYPT 2024, Part VI",
  series="Lecture Notes in Computer Science",
  volume="15489",
  year="2024",
  publisher="Springer Nature Singapore",
  pages="200--233",
  url="https://link.springer.com/chapter/10.1007/978-981-96-0938-3_7"
}
```
