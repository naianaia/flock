#!/usr/bin/env bash

scp -r ~/code/flock/* ml-box-sourceress:/home/jason/code/flock
ssh ml-box-sourceress "bash /home/jason/code/flock/devops/install-nginx-conf.sh"
ssh ml-box-sourceress "nginx -s reload"