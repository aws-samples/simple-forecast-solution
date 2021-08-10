# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
FROM amazonlinux:2
ARG username=ec2-user
SHELL ["/bin/bash", "-c"]

# Install system packages
RUN yum update -y \
    && yum install -y shadow-utils.x86_64 sudo git zip unzip wget which tar jq \
        gcc-c++ make patch openssl-devel zlib-devel readline-devel sqlite-devel \
        bzip2-devel libffi-devel \
    && yum clean all

# Install docker
# docker run -v /var/run/docker.sock:/var/run/docker.sock
RUN amazon-linux-extras install docker -y

# Create a non-root user
RUN groupadd -g 1000 $username \
    && useradd -d /home/$username -u 1000 -g 1000 -m -s /bin/bash $username

# Make the non-root user a sudoer
RUN echo "$username ALL=(root) NOPASSWD:ALL" > /etc/sudoers.d/$username && \
    chmod 0440 /etc/sudoers.d/$username

RUN usermod -aG docker $username

# Switch to the non-root user
USER $username
WORKDIR /home/$username

COPY --chown=$username:$username . /home/$username/
