# Eurosys 2022 Artifact

This artifact relates to the "Sharing is Caring: Secure and Efficient Shared Memory Support for MVEEs" paper submitted
to Eurosys 2022. All bash snippets in the steps below are assumed to start from the repository root.

## Prerequisites

For more reproducible results turn off hyperthreading and turbo boost. The method for this depends on your system.
General Intel way:

```bash

```

---

## Docker instructions

When prompted for a user password inside the container
- Docker container user: eval
- Docker container password: artifactdocker

### Step 0 - setting up the container

**Method 1**: using the included docker bash script

```bash
./eurosys2022-artifact/docker_control.sh build
```

**Method 2**: running docker command manually:

```bash
docker build ./eurosys2022-artifact/ -t shmvee:ae
```

### Step 1 - bootstrap

**Method 1**: using the included docker bash script

```bash
./eurosys2022-artifact/docker_control.sh bootstrap
```

**Method 2**: running docker command manually:

```bash
docker run                                                                             \
    -v "./:/home/eval/artifact/" --workdir="/home/eval/artifact/eurosys2022-artifact/" \
    --env BUILDALL=1 --name artifact -it shmvee:ae                                     \
    ./bootstrap.sh
docker commit artifact shmvee:ae
docker rm artifact
```

### Step 2 - run experiments

**Microbenchmark**: follow instructions in eurosys2022-artifact/wiki/microbenchmark.md

**Nginx**: follow instructions in eurosys2022-artifact/wiki/nginx.md

**Apache**: follow instructions in eurosys2022-artifact/wiki/apaches.md

**MPlayer**: follow instructions in eurosys2022-artifact/wiki/mplayer.md

## Native execution instructions

### Step 1 - bootstrap

```bash
BUILDALL=1 ./eurosys2022-artifact/bootstrap.sh
```

### Step 2 - run experiments

**Microbenchmark**: follow instructions in eurosys2022-artifact/wiki/microbenchmark.md

**Nginx**: follow instructions in eurosys2022-artifact/wiki/nginx.md

**Apache**: follow instructions in eurosys2022-artifact/wiki/apaches.md

**MPlayer**: follow instructions in eurosys2022-artifact/wiki/mplayer.md