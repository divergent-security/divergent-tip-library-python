#!/usr/bin/env bash
set -e

push_containers ()
{
	docker push us.gcr.io/sortermonkey-workers/sortermonkey-base-job:latest
}

docker build -t "us.gcr.io/sortermonkey-workers/sortermonkey-base-job:latest" .

while true; do
    read -p "Do you wish to push the docker containers?" yn
    case $yn in
        [Yy]* ) push_containers; break;;
        [Nn]* ) exit;;
        * ) echo "Please answer yes or no.";;
    esac
done
