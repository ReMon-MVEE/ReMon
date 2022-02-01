FROM ubuntu:18.04
ARG DEBIAN_FRONTEND=noninteractive
ARG __uid=1000
ARG __gid=1000
ARG __user=eval
ARG __password=artifactdocker

# Install the required packages
RUN                                                   \
    apt-get update                                 && \
    apt-get install -y git sudo openssh-server vim

# Enable deb-src
RUN sed -i 's/^#\sdeb-src/deb-src/' /etc/apt/sources.list

RUN useradd -rm -d /home/${__user} -s /bin/bash -g root -G sudo -u ${__uid} ${__user}
# super hacky, but hey, this works.
RUN echo "${__user}:${__password}" | chpasswd
USER ${__user}
WORKDIR /home/${__user}

RUN mkdir -p /home/eval/.ssh/
RUN git config --global credential.helper store
COPY --chown=eval:root id_rsa /home/eval/.ssh/id_rsa
COPY --chown=eval:root id_rsa.pub /home/eval/.ssh/id_rsa.pub
COPY --chown=eval:root .git-credentials /home/eval/.git-credentials

RUN chmod 400 /home/eval/.ssh/id_rsa*