# bitcoin-fuzzer
## Introduction
RSK works with a series of blockchain objects (blocks, headers, transactions, scripts etc.) received from the Bitcoin network, or sent to it. These objects are proxied by complex operations performed by the RSK Bridge. The Bridge is responsible for critical parsing of objects received from Bitcoin, as well as generating critical objects, to be sent to the Bitcoin network.

RSK needs a single framework that can be used to perform _unit_, _adversarial_ (fuzz/negative) and _integration_ tests with Bitcoin components. Bitcoin-fuzzer can work as a stand-alone framework or integrated with other tools, such as [Coinspect SRK](https://github.com/coinspect/srk).

Bitcoin-fuzzer is split in two key components
1. A Dockerfile that creates the runtime test environment
2. Coinspect's fuzzing harnesses codebase

**_Warning:_** This is an incipient work. As of now it is essentially a Bitcoin + Libfuzzer fork, with minor changes.
### Docker
[Ubuntu image](https://github.com/coinspect/bitcoin-fuzzer/blob/master/Dockerfile) with required dependencies and [Libfuzzer](https://github.com/google/fuzzing/blob/master/tutorial/libFuzzerTutorial.md).
### Test cases
Modified [Bitcoin harnesses](https://github.com/bitcoin/bitcoin/tree/master/src/test/fuzz) and [seed input](https://github.com/bitcoin-core/qa-assets) to fit RSK's needs. Details can be found in the [Architecture](/Architecture) section below.

## Architecture
Bitcoin supports a number of [fuzzers](https://github.com/bitcoin/bitcoin/blob/master/doc/fuzzing.md) to test different features. However, the regular Bitcoin fuzzing framework has a number of drawbacks for RSK's needs.

### Seed input
Bitcoin [seed input](https://github.com/bitcoin-core/qa-assets) are either unstructured or semi-structured.

Due to the complexity in parsing/generating blockchain objects from and to the Bitcoin network, testing RSK <> Bitcoin operations requires well controlled inputs.
The use of unstructured inputs to exercise RSK <> Bitcoin operations will lead to small or no coverage, adding little value to the framework.

### Fuzzing harnesses
Out-of-the-box [Bitcoin harnesses](https://github.com/bitcoin/bitcoin/tree/master/src/test/fuzz) provide interfaces for different features of the blockchain, working as follows:

1. Fuzz _target_ (e.g.: "script") consumes seed input in binary form provided set of _seed inputs_
2. Target harness uses LLVM ```FuzzedDataProvider``` together with a number of Bitcoin-provided ```Consume*{TYPE}``` helper functions do receive data input.
3. Iterate over input seeds and performs mutations

Some Bitcoin harnesses will have field-oriented mutation operations. However, even those that do, depend on seed input to be structured to make mutations only on specified fields.

### Bitcoin-fuzzer architecture
Aiming to test specific features of the RSK <> Bitcoin integration, we propose the following workflow to create tests and negative tests:
1. Use SRK or another tool to generate _valid inputs_ (e.g. transactions or scripts)
2. Create target harnesses to consume inputs and work on field level (for example, applying mutations applicable to object type)
3. Iterate over series of inputs performing checks and validation logics of will

## Usage
```$ git clone https://github.com/coinspect/bitcoin-fuzzer.git```

```$ cd bitcoin-fuzzer```

```$ docker build -t bitcoin-fuzzer .```

Once done building, open a terminal with the docker instance.

Make edits to harnesses:

```$ cd /usr/src/bitcoin/src/test/fuzz```

Run fuzz targets with provided seed input:

```$ cd /usr/src/bitcoin/test/fuzz```

```./test_runner.py --corpus_dir ./json-input --target script```








