#!/usr/bin/env bash

scp -r /Users/absentious/Documents/workspace/house/flock/* jason@192.168.86.131:/home/jason/code/flock
#ssh ml-box-sourceress "bash /home/jason/code/flock/devops/install-nginx-conf.sh"
#ssh ml-box-sourceress "nginx -s reload"