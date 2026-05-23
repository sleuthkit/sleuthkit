# Dockerfile to create an ubuntu_x86 image that we can use for compiling and testing
# Debian TSK with x86 architecture on other systems (e.g. x86 Winodws, Arm Windows, Arm MacOS)

# Use the official Ubuntu image
FROM ubuntu:latest

# Set non-interactive mode for apt
ENV DEBIAN_FRONTEND=noninteractive

# Update and install common tools
RUN apt update && apt upgrade -y && \
    apt install -y \
    ant \
    automake \
    build-essential \
    curl \
    debhelper \
    devscripts \
    dh-make \
    dnsutils \
    docker.io \
    emacs \
    g++ \
    gcc \
    git \
    iproute2 \
    libc3p0-java \
    libpostgresql-jdbc-java \
    libsqlite3-dev \
    libtool \
    lintian \
    make \
    nano \
    net-tools \
    nodejs \
    npm \
    openjdk-17-jdk-headless \
    openssh-client \
    python3 \
    python3-pip \
    sudo \
    unzip \
    vim \
    wget \
    zip

# Install things specifically for building TSK
RUN apt install -y libewf-dev libvmdk-dev libvhdi-dev

RUN apt clean && rm -rf /var/lib/apt/lists/*

# Ensure sudo is available without a password for the default user
RUN mkdir -p /etc/sudoers.d && \
    echo "ubuntu ALL=(ALL) NOPASSWD:ALL" > /etc/sudoers.d/ubuntu && \
    chmod 0440 /etc/sudoers.d/ubuntu

# Explicitly add 'ubuntu' user to sudo group
RUN usermod -aG sudo ubuntu

# Ensure Ubuntu has a proper directory
RUN mkdir -p /home/ubuntu/.ssh && touch /home/ubuntu/.ssh/authorized_keys
RUN chmod 700 /home/ubuntu/.ssh && chmod 600 /home/ubuntu/.ssh/* && chown -R ubuntu /home/ubuntu/.ssh

# Switch to the default user that already exists in Ubuntu images
USER ubuntu
WORKDIR /home/ubuntu

# Set default shell
CMD ["/bin/bash"]
