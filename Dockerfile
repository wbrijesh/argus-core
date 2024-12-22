FROM golang:1.23-alpine AS build

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN go build -o main cmd/api/main.go

FROM alpine:3.20.1 AS prod
WORKDIR /app
COPY --from=build /app/main /app/main
# COPY temp_file.der /app/temp_file.der
# COPY sf-class2-root.crt /app/sf-class2-root.crt
# COPY cassandra_truststore.jks /app/cassandra_truststore.jks
EXPOSE ${PORT}
CMD ["./main"]
