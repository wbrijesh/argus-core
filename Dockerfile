FROM golang:1.23-alpine AS build

WORKDIR /app

COPY go.mod go.sum ./
COPY vendor/ ./vendor/

COPY . .

RUN go build -o main cmd/api/main.go

FROM scratch AS prod
WORKDIR /app
COPY --from=build /app/main /app/main

COPY ./cassandra_ca.crt /app/cassandra_ca.crt

EXPOSE ${PORT}
CMD ["./main"]
