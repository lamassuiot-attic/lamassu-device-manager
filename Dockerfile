FROM golang:1.16
WORKDIR /app
COPY . .
WORKDIR /app/cmd/devices
ENV GOSUMDB=off
WORKDIR /app
RUN CGO_ENABLED=0 go build -mod=vendor  -o devices ./cmd/main.go

FROM scratch
COPY --from=0 /app/devices /
CMD ["/devices"]