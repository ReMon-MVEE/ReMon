#!/bin/bash
set -e

if ! command -v docker &> /dev/null; then
    echo "Docker is required to run this script"
    exit 1
fi


__home_dir="$(readlink -f $(dirname ${BASH_SOURCE}))"


__docker_image="shmvee:ae"
__volumes="-v $__home_dir/../:/home/eval/artifact/"
__ports="-p 8080:8080"


build_docker() {
    docker build $__home_dir -t $__docker_image
}


bootstrap_docker() {
    docker run                                                           \
        $__volumes --workdir="/home/eval/artifact/eurosys2022-artifact/" \
        --env BUILDALL=1 --name artifact -it $__docker_image             \
        ./bootstrap.sh
    docker commit artifact $__docker_image
    docker rm artifact
}


build_all_docker() {
    docker run                                                           \
        $__volumes --workdir="/home/eval/artifact/eurosys2022-artifact/" \
        -it $__docker_image                                              \
        ./benchmarks/scripts/build_all.sh
}


run_docker() {
    docker run                                               \
        --security-opt seccomp=unconfined                    \
        $__volumes $__ports --workdir="/home/eval/artifact/" \
        --rm -it $__docker_image $1
}


run_x11docker() {
    if ! command -v x11docker &> /dev/null; then
        echo "No x11docker installed! Download at https://github.com/mviereck/x11docker"
        exit 1
    fi

    x11docker --hostdisplay --hostipc --gpu --pulseaudio --interactive \
        --user=RETAIN --network --clipboard --cap-default              \
        --workdir=/home/eval/artifact --                               \
        --cap-add SYS_PTRACE -ti $__volumes $__ports --                \
        $__docker_image $1
}


# Check the number of parameters
if [ "$#" -ne 1 ]; then
    echo "No mode specified, trying to just run the docker."
    __mode="run"
else
    __mode="$1"
fi

case "$__mode" in
    build)
        build_docker
        ;;

    build-all)
        build_all_docker
        ;;

    bootstrap)
        bootstrap_docker
        ;;

    run)
        shift
        if [ "$#" -ne 1 ]; then
            echo "No command specified, running bash shell in docker."
            run_docker "bash"
        else
            run_docker "$1"
        fi
        ;;

    runx11)
        shift
        if [ "$#" -ne 1 ]; then
            echo "No command specified, running bash shell in docker."
            run_x11docker "bash"
        else
            run_x11docker "$1"
        fi
        ;;

    *)
        echo "Invalid mode specified!"
        exit 2
        ;;
esac
