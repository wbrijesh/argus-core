package database

import (
	"fmt"
	"log"
	"os"

	"github.com/gocql/gocql"
	_ "github.com/joho/godotenv/autoload"
)

func New() Service {
	// Load environment variables
	cassandraHost := os.Getenv("CASSANDRA_HOST")
	cassandraUsername := os.Getenv("CASSANDRA_USERNAME")
	cassandraPassword := os.Getenv("CASSANDRA_PASSWORD")
	cassandraKeyspace := os.Getenv("CASSANDRA_KEYSPACE")

	cluster := gocql.NewCluster(cassandraHost)
	cluster.Port = 9142
	cluster.SslOpts = nil
	cluster.Authenticator = gocql.PasswordAuthenticator{
		Username: cassandraUsername,
		Password: cassandraPassword,
	}
	cluster.SslOpts = &gocql.SslOptions{
		CaPath:                 "cassandra_ca.crt",
		EnableHostVerification: false,
	}
	cluster.Consistency = gocql.LocalQuorum
	cluster.Keyspace = cassandraKeyspace

	session, err := cluster.CreateSession()
	if err != nil {
		log.Fatal("Failed to create Cassandra session:", err)
	}

	return &service{session: session}
}

func (s *service) Health() map[string]string {
	stats := make(map[string]string)

	if err := s.session.Query("SELECT release_version FROM system.local").Exec(); err != nil {
		stats["status"] = "down"
		stats["error"] = fmt.Sprintf("Cassandra down: %v", err)
		return stats
	}

	stats["status"] = "up"
	stats["message"] = "Cassandra is healthy"
	return stats
}

func (s *service) Close() error {
	s.session.Close()
	return nil
}
