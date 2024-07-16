FROM golang:1.22 AS builder

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 go build -ldflags '-s -w -extldflags "-static"' -a -o main .

FROM scratch

COPY --from=builder /app/main /oneshell
ENTRYPOINT [ "/oneshell" ]