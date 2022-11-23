# Bitcoin-fuzzer
## Introduction
RSK works with a series of blockchain objects (blocks, headers, transactions, scripts etc.) received from the Bitcoin network, and sent to it. These objects are proxied by complex operations performed by the RSK Bridge. The Bridge is responsible for critical parsing of objects received from Bitcoin, as well as generating objects, to be sent to the Bitcoin network.

Incorrect handling or generation of aforementioned objects can lead to severe issues in the RSK <> Bitcoin integration.

RSK needs a single framework that can be used to perform _unit_, _adversarial_ (fuzz/negative) and _integration_ tests with Bitcoin components in order to identify such issues before deployment.

Bitcoin-fuzzer is a modified version of the Bitcoin core unit tests framework with Libfuzzer. It supports two modes of operation:
* Bitcoin-tests ("tests"), allowing to execute the original Bitcoin unit tests + Bitcoin-fuzzer's additional cases
* Bitcoin-fuzzer ("fuzzer"), allowing to execute the original Bitcoin fuzzing harnesses + Bitcoin-fuzzer's additional cases

It can work as a stand-alone framework or interface with other tools, such as [Coinspect SRK](https://github.com/coinspect/srk). Bitcoin-fuzzer comes with the extensive collection of tests and input data from the Bitcoin repository, with addition to:
* Special test cases to RSK
* A unified interface to receive inputs from JSON files, working for both Bitcoin unit tests and Libfuzzer harnesseses.

Bitcoin-fuzzer is split in three key components
1. A Dockerfile to create the test environment
2. [Unit tests](https://github.com/bitcoin/bitcoin/tree/master/src/test/) and modified [fuzzing harnesses](https://github.com/bitcoin/bitcoin/tree/master/src/test/fuzz)
3. [Input data](https://github.com/bitcoin/bitcoin/tree/master/src/test/data)

Notice that the original fuzzing [seed input](https://github.com/bitcoin-core/qa-assets) containing unstructured data is replaced with well-formed JSONs. This allows better coverage and more intelligent testing.

## Usage

``` sh
$ git clone https://github.com/coinspect/bitcoin-fuzzer
$ cd bitcoin-fuzzer
# Optionally, add/modify input data sets of your choice into inputs/
# Build it
$ docker build -t bitcoin-fuzzer . --build-arg arg={'tests','fuzzer'}
# You can re-run the test cases, for example "script_test"
$ docker run bitcoin-test /usr/src/bitcoin/src/test/test_bitcoin --run_test=script_test
# Or fuzzing harnesses
$ docker run bitcoin-test /usr/src/bitcoin/test/fuzz/test-runner.py --corpus_dir /inputs --target script

```
If you want to modify the currently existent tests, or add new cases, edit the C++ modules and rebuild the image. The same procedure can be performed to change or add new input data: make the necessary changes to inputs and rebuild the Docker image.
