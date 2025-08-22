# Licensed under the Apache-2.0 license
FROM ubuntu:22.04

# Install build tools.
RUN apt update && apt install gcc git curl make gcc-aarch64-linux-gnu  -y
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
ENV PATH="/root/.cargo/bin:${PATH}"
RUN rustup target add riscv32imc-unknown-none-elf && rustup target add aarch64-unknown-linux-gnu
RUN cargo install cargo-nextest

# Always trust the working directory where the git repo will be mounted.
RUN git config --global --add safe.directory /work-dir
