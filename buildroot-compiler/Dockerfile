# Pinned Debian stable image for deterministic Buildroot compilation
FROM debian:bookworm-20240211-slim

# Install system dependencies required for Buildroot compilation
RUN apt-get update && apt-get install -y \
    bc \
    build-essential \
    bzr \
    cvs \
    git \
    mercurial \
    subversion \
    libncurses5-dev \
    unzip \
    rsync \
    file \
    wget \
    cpio \
    python3 \
    python3-pip \
    libelf-dev \
    libssl-dev \
    qemu-utils \
    genimage \
    && rm -rf /var/lib/apt/lists/*

# Set build directory
WORKDIR /build

# Clone Buildroot LTS release (2024.02.x) and pin to a stable hash
RUN git clone --depth 1 --branch 2024.02.x https://github.com/buildroot/buildroot.git

WORKDIR /build/buildroot

# Define build arguments
ENV FORCE_UNSAFE_CONFIGURE=1
ENV SOURCE_DATE_EPOCH=1700000000
ENV TZ=UTC

# Run Buildroot compiler script
CMD ["/build/buildroot/board/subzero/build_image.sh"]
