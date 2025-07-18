# Racing-LLM
## Evaluate Cases 21 and 22 / Evaluate Examples 21 and 22


- Step 1: Set up and run the Docker environment (as introduced below).
- Step 2: Compile InstTracer, AFL, and LLVM Passes (as introduced below).
- Step 3: Change directory into example 21 or 22, and run:
    *   `./01_build_trace.sh`
    *   `./02_PoCExecutionInspector.sh`
    *   `./03_build_fuzz.sh`
- Step 4: Set the `$GEMINI_API_KEY` environment variable and run `./llm_rca_top_k.sh`.
- Step 5: The result will be written to `./analysis_reports_manual/gemini_rca_report.json`.

## Evaluate ezXML Zero-Day Simulation

- Step 1: Set up and run the Docker environment (as introduced below).
- Step 2: Compile InstTracer, AFL, and LLVM Passes (as introduced below).
- Step 3: Change directory into example 21 or 22, and run `./01_build_trace.sh`.
- Step 4: Copy the content of `ezxml_zero.c` and **overwrite** `./ezxml/ezxml.c`.
- Step 5: Run:
    *   `./02_PoCExecutionInspector.sh`
    *   `./03_build_fuzz.sh`
- Step 6: Set the `$GEMINI_API_KEY` environment variable and run `./llm_rca_top_k.sh`.
- Step 7: The result will be written to `./analysis_reports_manual/gemini_rca_report.json`.

# Racing on the Negative Force: Efficient Vulnerability Root-Cause Analysis through Reinforcement Learning on Counterexamples

Racing is an efficient statistical Root-Cause Analysis (RCA) solution that employs reinforcement learning. This repository contains the proof-of-concept implementation of our [paper](https://www.usenix.org/conference/usenixsecurity24/presentation/xu).

<p align="center">
<a href="https://www.usenix.org/conference/usenixsecurity24/presentation/xu-dandan"> <img alt="racing paper" width="200"  src="paper.jpg"></a>
</p>

## System Requirement

Racing was evaluated on an x86 Ubuntu 20.04 machine. Before you start everything, make sure to set the following configurations on your host machine (as required by AFL fuzzing).

```
### use root permission if necessary

echo core >/proc/sys/kernel/core_pattern
cd /sys/devices/system/cpu
echo performance | tee cpu*/cpufreq/scaling_governor

# disable ASLR
echo 0 | tee /proc/sys/kernel/randomize_va_space
```

## TL;DR

You may use our [Dockerfile](Dockerfile) to setup a testing environment. It automatically performs steps `S1 & S2` below. After the image has been built, please jump to step `S3` to run the commands inside the `racing-eval` container.

```bash
# 1. build racing-eval image
docker build -t racing-eval:latest .
# 2. run racing-eval container
docker run --name racing-eval --init -d -v $PWD/examples:/Racing-eval/examples racing-eval:latest tail -f /dev/null
# 3. attach to the container
docker exec -ti racing-eval bash
```

## S1. Environment Setup

To obtain a clean environment for testing, one can pull the `ubuntu:20.04` image and launch the following container.
```
# download racing code
git clone https://github.com/RacingN4th/racing-code
export RACING_DIR=$PWD/racing-code
# pull and launch container
docker pull ubuntu:20.04
docker run --name racing-eval -v ${RACING_DIR}:/Racing-final -d -it ubuntu:20.04 bash
```
Then attach into the container and install the following dependencies
```
docker exec -it racing-eval bash

### run commands below inside container
apt-get update
apt-get install -y wget make gcc clang-6.0
wget -c http://software.intel.com/sites/landingpage/pintool/downloads/pin-3.15-98253-gb56e429b1-gcc-linux.tar.gz
tar -xzf pin*.tar.gz
export PIN_ROOT="$PWD/pin-3.15-98253-gb56e429b1-gcc-linux"
```

## S2. Racing Build Steps

Racing consists of the following components
- `InstTracer`: A simple tracer to extract instructions that are covered by a vulnerability PoC.
- `Racing-final/afl-fuzz`: A modified implementation of the AFL fuzzer that integrates our reinforcement learning algorithm for efficient RCA.
- `Racing-final/llvm_mode/afl-llvm-pass.so`: An LLVM pass that instruments the PoC-related instructions for tracing their runtime values during fuzzing.
- `scripts`: auxiliary scripts used by Racing.

Building the above components require the following steps
```
# build InstTracer (make sure env PIN_ROOT is set)
cd ${RACING_DIR}/InstTracer
make

# build afl-fuzz
cd ${RACING_DIR}/Racing-final
make

# build llvm pass
cd ${RACING_DIR}/Racing-final/llvm_mode
make
```

## S3. Testing Steps

The `examples` folder contains the scripts for analyzing the 30 vulnerabilities used in our paper. To reproduce it, please refer to the following example:
```bash
cd examples/21-ezXML-nullptr-dereference

# step 1: download source code and build a binary for tracing
./01_build_trace.sh
# step 2: trace the binary's execution with PoC as input
./02_PoCExecutionInspector.sh
# step 3: build a binary for racing's fuzzing process
./03_build_fuzz.sh
# step 4: start racing's fuzzing process (rca)
./04_racing.sh
```

After the above steps, please check `afl-workdir-batch0/ranked_file` for the ranking of predicates.

> [!WARNING]  
> When compiling the binary using racing's afl-clang-fast, please *DO NOT* enable `-j` as racing needs to generate sequential IDs for instructions.


## Cite our paper

Please cite Racing use the following BibTex code:

```
@inproceedings{xu2024racing,
    title = {Racing on the Negative Force: Efficient Vulnerability Root-Cause Analysis through Reinforcement Learning on Counterexamples},
    author = {Xu, Dandan and Tang, Di and Chen, Yi and Wang, XiaoFeng and Chen, Kai and Tang, Haixu and Li, Longxing},
    year = {2024}
    booktitle = {33rd {USENIX} Security Symposium ({USENIX} Security 24)},
}
```
