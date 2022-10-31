# Bitcoin-fuzzer
## Introduction
RSK works with a series of blockchain objects (blocks, headers, transactions, scripts etc.) received from the Bitcoin network, and sent to it. These objects are proxied by complex operations performed by the RSK Bridge. The Bridge is responsible for critical parsing of objects received from Bitcoin, as well as generating objects, to be sent to the Bitcoin network.

Incorrect handling or generation of aforementioned objects can lead to severe issues in the RSK <> Bitcoin integration.

RSK needs a single framework that can be used to perform _unit_, _adversarial_ (fuzz/negative) and _integration_ tests with Bitcoin components in order to identify such issues before deployment.

Bitcoin-fuzzer aims to be a slightly modified version of Bitcoin + Libfuzzer, which can work as a stand-alone framework or interface with other tools, such as [Coinspect SRK](https://github.com/coinspect/srk). For such, Bitcoin-fuzzer proposes minor changes in how Bitcoin + Libfuzzer consume and modify input data.

Bitcoin-fuzzer is split in two key components
1. A Dockerfile that creates the runtime test environment
2. Modified fuzzing harnesses to generate **structured inputs** only

**_Warning:_** This is an incipient work. As of now it is essentially a Bitcoin + Libfuzzer fork, with minor changes.
### Docker
[Ubuntu image](https://github.com/coinspect/bitcoin-fuzzer/blob/master/Dockerfile) with required dependencies and [Libfuzzer](https://github.com/google/fuzzing/blob/master/tutorial/libFuzzerTutorial.md).
### Test cases
Modified [Bitcoin harnesses](https://github.com/bitcoin/bitcoin/tree/master/src/test/fuzz) and [seed input](https://github.com/bitcoin-core/qa-assets) to fit RSK's needs.

## Architecture
Bitcoin supports a number of [fuzzers](https://github.com/bitcoin/bitcoin/blob/master/doc/fuzzing.md) to test different features. However, the original Bitcoin fuzzing framework has one drawback to RSK's needs: **use of unstructured data.**

### Original seed input
_Original Bitcoin_ [seed input](https://github.com/bitcoin-core/qa-assets) are either unstructured or semi-structured.

Due to the complexity in parsing/generating blockchain objects from and to the Bitcoin network, testing RSK <> Bitcoin operations requires **well controlled inputs** to make precise tests.
The use of unstructured inputs to exercise RSK <> Bitcoin operations will lead to small or no coverage, adding little value to the framework.

### Original fuzzing harnesses
**Original** [Bitcoin harnesses](https://github.com/bitcoin/bitcoin/tree/master/src/test/fuzz) provide interfaces for different features of the blockchain, working as follows:

1. Fuzz _target_ (e.g.: "script") provides a set of **unstructured input** data on disk
2. Target harness: uses LLVM ```FuzzedDataProvider``` together with a number of Bitcoin-provided ```Consume*{TYPE}``` helper functions do receive data input.
3. Target harness: iterates over input seeds and performs mutations

The result is that no matter how smart mutations are performed, the result is always **unstructured data**, which is not useful to test RSK <> Bitcoin.

### Modified Bitcoin-fuzzer architecture
Aiming to resolve **unstructured input**, we propose the following workflow:
1. Use SRK or another tool to save **structured inputs** (e.g. parseable transactions or scripts) to disk
2. Modify original fuzzing harnesses to consume **structured inputs** and mutate it without breaking structure
3. Iterate over inputs performing checks and validation logics defined by the user

## Usage

``` sh
$ git clone https://github.com/coinspect/bitcoin-fuzzer
$ cd bitcoin-fuzzer
$ docker build -t bitcoin-fuzzer .

# we will now build the volume with inputs for bitcoind to run
$ mkdir inputs; mkdir inputs/script

# $INPUTS is a JSON file with testcases
$ cp $INPUTS inputs/inputs.json 
$ cd inputs/script

# we need to split the input file because of the buffer size of 
# the C code
$ jq -c '.[]' ../inputs.json | split -l 100 

$ cd ../.. # back to project root folder
$ docker run -it -v $PWD/inputs/:/inputs bitcoin-fuzzer /bin/bash

# you are now inside the docker container
> cd /usr/bitcoin/test/fuzz 
> ./test-runner.py --corpus_dir /inputs --target script
```
