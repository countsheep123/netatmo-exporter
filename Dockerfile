FROM golang:latest

RUN go get gitlab.com/countsheep123/netatmo-exporter/...

ENTRYPOINT $GOPATH/bin/netatmo-exporter
