#!/usr/bin/env bash

docker run -p 1884:1883 -p 8005:8003 \
        -v /home/jason/flock/data:/data \
        -e MQTT_ADMIN='admin' \
        -e MQTT_PASS='password' \
        -e MQTT_SERVER='localhost:1883' \
        -e MQTT_EXTERNAL='192.168.86.131' \
        -e MQTT_PORT=1884 \
        --name find3server -d -t schollz/find3