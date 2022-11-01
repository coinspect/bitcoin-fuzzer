
FROM ubuntu:22.04

EXPOSE 8332 8333

ARG BASIC_PACKAGES="build-essential libtool autotools-dev automake pkg-config python3 git wget ca-certificates libssl-dev libevent-dev libboost-system-dev libboost-filesystem-dev libboost-chrono-dev libboost-thread-dev libboost-program-options-dev ccache"
ARG FUZZER_PACKAGES="clang llvm libfuzzer-13-dev"
ARG OPTIONAL_PACKAGES="vim zsh"
ARG BITCOIN_PATH="/usr/src/bitcoin"
ARG COINSPECT_FUZZER_PACKAGE="coinspect-bitcoin-fuzzer"

RUN apt-get update && \
	apt-get install -y $BASIC_PACKAGES && \
	apt-get install -y $FUZZER_PACKAGES && \
	apt-get install -y $OPTIONAL_PACKAGES && \
	cd /usr/src/ && \
	git clone https://github.com/bitcoin/bitcoin.git

COPY $COINSPECT_FUZZER_PACKAGE/ $BITCOIN_PATH

RUN cd $BITCOIN_PATH && \
	./autogen.sh && \
	CC=clang CXX=clang++ ./configure --enable-fuzz --with-sanitizers=address,fuzzer,undefined && \
	make

