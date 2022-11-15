FROM ubuntu:22.04

EXPOSE 8332 8333

ARG FUZZER_PACKAGES="build-essential libtool autotools-dev automake pkg-config python3 git wget ca-certificates libssl-dev libevent-dev libboost-system-dev libboost-filesystem-dev libboost-chrono-dev libboost-thread-dev libboost-program-options-dev ccache clang llvm libfuzzer-13-dev"

ARG UNITTESTS_PACKAGES="build-essential libtool autotools-dev automake pkg-config bsdmainutils python3 git libevent-dev libboost-dev"

ARG OPTIONAL_PACKAGES="vim zsh"
ARG BITCOIN_PATH="/usr/src/bitcoin"
ARG BITCOIN_INPUT_DATA="/usr/src/bitcoin/src/test/data"
ARG COINSPECT_PACKAGE="coinspect-bitcoin-fuzzer"
ARG COINSPECT_INPUT_DATA="input"
ARG COINSPECT_INPUT_FILES="deprecated_ERP_scripts.json new_ERP_scripts.json pegfix_overflow_scripts.json scripts_fastbridge.json"

ARG arg
RUN	apt-get update && \
	if [ "$arg"  = "tests" ] ; then \
		apt-get install -y $UNITTESTS_PACKAGES; \
	elif [ "$arg"  = "fuzzer" ] ; then \
		apt-get install -y $FUZZER_PACKAGES; \
	else \
		echo "Choose one option: --build-arg arg={'tests','fuzzer'}."; \
		exit 1; \
	fi && \
	apt-get install -y $OPTIONAL_PACKAGES && \
	cd /usr/src/ && \
	git clone https://github.com/bitcoin/bitcoin.git

COPY $COINSPECT_PACKAGE/src/Makefile.test.include $BITCOIN_PATH/src
WORKDIR $BITCOIN_INPUT_DATA
RUN touch $COINSPECT_INPUT_FILES

RUN	cd $BITCOIN_PATH && \
	./autogen.sh && \
	if [ "$arg"  = "tests" ] ; then \
		./configure; \
	elif [ "$arg"  = "fuzzer" ] ; then \
		CC=clang CXX=clang++ ./configure --enable-fuzz --with-sanitizers=address,fuzzer,undefined,signed-integer-overflow,unsigned-integer-overflow; \
	fi

	RUN cd $BITCOIN_PATH && \
	if [ "$arg"  = "tests" ] ; then \
		make -C src/test -j "$(($(nproc)+1))"; \
	elif [ "$arg"  = "fuzzer" ] ; then \
		make -j "$(($(nproc)+1))"; \
	fi

WORKDIR $BITCOIN_INPUT_DATA
RUN rm *.h

COPY $COINSPECT_PACKAGE $BITCOIN_PATH
COPY $COINSPECT_INPUT_DATA $BITCOIN_INPUT_DATA

RUN cd $BITCOIN_PATH && \
	if [ "$arg"  = "tests" ] ; then \
		make -C src/test -j "$(($(nproc)+1))"; \
        src/test/test_bitcoin --run_test=script_tests; \
	elif [ "$arg"  = "fuzzer" ] ; then \
		make -j "$(($(nproc)+1))"; \
        test/fuzz/test-runner.py --corpus_dir test/fuzz/json-input --target script; \
	fi

