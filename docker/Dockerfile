FROM ubuntu:bionic

LABEL maintainer="Polymath Inc"
LABEL name="rust"
LABEL version="latest"

ENV DEBIAN_FRONTEND noninteractive

ARG NIGHTLY_VERSION=nightly-2021-04-24

RUN apt-get update && \
    apt-get install cmake pkg-config git gcc build-essential git clang openssh-client \
        libclang-dev curl ca-certificates libssl-dev -y --no-install-recommends && \
    curl https://sh.rustup.rs -sSf | sh -s -- -y && \
    curl -sL https://deb.nodesource.com/setup_12.x | bash - && \
    curl -sL https://dl.yarnpkg.com/debian/pubkey.gpg | apt-key add - && \
    echo "deb https://dl.yarnpkg.com/debian/ stable main" | tee /etc/apt/sources.list.d/yarn.list && \
    apt-get install nodejs g++ make yarn -y --no-install-recommends && \
    apt-get autoremove -y && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

ENV PATH=/root/.cargo/bin:$PATH

RUN rustup update $NIGHTLY_VERSION && \
    rustup component add rustfmt --toolchain $NIGHTLY_VERSION && \
    rustup component add clippy --toolchain $NIGHTLY_VERSION && \
    rustup target add wasm32-unknown-unknown --toolchain $NIGHTLY_VERSION && \
    ln -s ~/.rustup/toolchains/${NIGHTLY_VERSION}-x86_64-unknown-linux-gnu ~/.rustup/toolchains/nightly-x86_64-unknown-linux-gnu && \
    cargo --version && \
    cargo +nightly --version && \
    cargo +$NIGHTLY_VERSION --version && \
    nodejs --version
    
RUN cargo install --git https://github.com/rustwasm/wasm-pack wasm-pack
