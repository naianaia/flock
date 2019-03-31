# flock

To run:
1. Start find3 server with Docker via `bash devops/run.sh`
2. Start web process with `honcho start`
3. Make sure nginx is running

## Docker
Down: sudo docker stop find3server; sudo docker rm find3server
Up: ./devops/run.sh

FLASK_DEBUG=1 FLASK_APP=server FLASK_ENV=development FLASK_RUN_PORT=8004 flask run

FLASK_DEBUG=1 FLASK_APP=server FLASK_ENV=development FLASK_RUN_PORT=8005 flask run