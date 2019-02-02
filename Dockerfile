FROM golang:1.11.5-alpine3.8 AS builder

RUN apk add --update --no-cache git ca-certificates

WORKDIR /opt

COPY ./ ./

ENV CGO_ENABLED=0

RUN go mod download
RUN go build -o /opt/netatmo-exporter /opt/cmd/netatmo-exporter/main.go

FROM scratch

COPY --from=builder /opt/netatmo-exporter /opt/netatmo-exporter
COPY --from=builder /etc/ssl/certs /etc/ssl/certs

ENTRYPOINT ["/opt/netatmo-exporter"]
