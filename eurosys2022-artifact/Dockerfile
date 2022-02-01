FROM ubuntu:18.04
ARG DEBIAN_FRONTEND=noninteractive

# Install the required packages
RUN                                                                                                                      \
    apt-get update                                                                                                    && \
    apt-get install -y git sudo openssh-server vim

# Enable deb-src
RUN sed -i 's/^#\sdeb-src/deb-src/' /etc/apt/sources.list

RUN useradd -rm -d /home/eval -s /bin/bash -g root -G sudo -u 1000 eval
# super hacky, but hey, this works.
RUN yes artifactdocker | passwd eval
USER eval
WORKDIR /home/eval

RUN mkdir -p /home/eval/.ssh/
RUN git config --global credential.helper store
COPY --chown=eval:root id_rsa /home/eval/.ssh/id_rsa
COPY --chown=eval:root id_rsa.pub /home/eval/.ssh/id_rsa.pub
COPY --chown=eval:root .git-credentials /home/eval/.git-credentials

RUN chmod 400 /home/eval/.ssh/id_rsa*