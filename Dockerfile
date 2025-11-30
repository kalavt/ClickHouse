# ----------------------
# Stage 1: Builder (compile source code)
# ----------------------
FROM clickhouse/binary-builder:latest AS builder

WORKDIR /clickhouse

# ----------------------
# Copy source code including submodules
# Note: GitHub Actions should checkout with submodules initialized
# ----------------------
COPY . /clickhouse

# Prepare build directory and cache build steps
RUN mkdir -p build && cd build \
    && cmake .. -DCMAKE_BUILD_TYPE=Release \
    && make -j1 clickhouse || true  # generate cache without failing

# Incremental build: only recompile modified sources
RUN cd build \
    && make -j$(nproc)

# ----------------------
# Stage 2: Runtime
# ----------------------
FROM clickhouse/clickhouse-server:latest

# Copy the custom compiled binary
COPY --from=builder /clickhouse/build/programs/clickhouse /usr/bin/clickhouse
