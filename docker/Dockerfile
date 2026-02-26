# Softy Tools Container
# Contains: Ghidra 11.3 + OpenJDK 21 + Radare2 + LLVM/Clang 17 + NASM + Python 3.12 + lief
FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive
ENV GHIDRA_VERSION=11.3
ENV GHIDRA_DATE=20250205
ENV GHIDRA_HOME=/opt/ghidra

# ── System packages ────────────────────────────────────────────────────────────
RUN apt-get update && apt-get install -y --no-install-recommends \
    # Java for Ghidra
    openjdk-21-jre-headless \
    # Build tools & utilities
    curl wget unzip git file binutils \
    # LLVM/Clang toolchain
    clang-17 llvm-17 lld-17 \
    # NASM assembler
    nasm \
    # Radare2 (from apt — Ubuntu 24.04 has r2 5.x)
    radare2 \
    # Python runtime
    python3.12 python3.12-dev python3-pip python3.12-venv \
    # libmagic for file detection
    libmagic1 \
    # Required for lief native compilation
    cmake build-essential \
  && rm -rf /var/lib/apt/lists/*

# Symlink clang-17 → clang for convenience
RUN update-alternatives --install /usr/bin/clang clang /usr/bin/clang-17 100 \
 && update-alternatives --install /usr/bin/clang++ clang++ /usr/bin/clang++-17 100 \
 && update-alternatives --install /usr/bin/llvm-objdump llvm-objdump /usr/bin/llvm-objdump-17 100

# ── Ghidra ────────────────────────────────────────────────────────────────────
RUN wget -q "https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_${GHIDRA_VERSION}_build/ghidra_${GHIDRA_VERSION}_PUBLIC_${GHIDRA_DATE}.zip" \
      -O /tmp/ghidra.zip \
 && unzip -q /tmp/ghidra.zip -d /opt \
 && mv /opt/ghidra_${GHIDRA_VERSION}_PUBLIC ${GHIDRA_HOME} \
 && rm /tmp/ghidra.zip

# ── Python API server dependencies ───────────────────────────────────────────
WORKDIR /app
COPY server/requirements.txt .
RUN pip3 install --no-cache-dir --break-system-packages -r requirements.txt

# ── Ghidra scripts ────────────────────────────────────────────────────────────
COPY ghidra_scripts/ /ghidra_scripts/

# ── API server source ─────────────────────────────────────────────────────────
COPY server/ /app/

# ── Work & project directories ─────────────────────────────────────────────────
RUN mkdir -p /work /ghidra-projects

# ── Expose ────────────────────────────────────────────────────────────────────
EXPOSE 7800

CMD ["python3", "-m", "uvicorn", "main:app", "--host", "0.0.0.0", "--port", "7800", "--log-level", "info"]
