package audit

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	_ "embed"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"

	"github.com/jackc/pgx/v5"
)

// GenesisHash is prev_hash for seq 1 of every chain.
var GenesisHash = make([]byte, sha256.Size)

// LinkHash is the chain function. Both the writer and the verifier use it;
// it is deliberately tiny so it can be re-implemented independently.
func LinkHash(prev []byte, chainID int32, seq int64, event []byte) []byte {
	h := sha256.New()
	h.Write(prev)
	var buf [12]byte
	binary.BigEndian.PutUint32(buf[0:4], uint32(chainID))
	binary.BigEndian.PutUint64(buf[4:12], uint64(seq))
	h.Write(buf[:])
	h.Write(event)
	return h.Sum(nil)
}

//go:embed schema.sql
var schemaSQL string

// Migrate creates the schema, append-only triggers and least-privilege roles.
// It must run as a role that owns the table (not the writer).
func Migrate(ctx context.Context, adminDSN, writerPassword, readerPassword string) error {
	conn, err := pgx.Connect(ctx, adminDSN)
	if err != nil {
		return err
	}
	defer conn.Close(ctx)
	if _, err := conn.Exec(ctx, schemaSQL); err != nil {
		return fmt.Errorf("schema: %w", err)
	}
	for _, r := range []struct{ name, pw, grants string }{
		{"agentgate_writer", writerPassword, "SELECT, INSERT"},
		{"agentgate_reader", readerPassword, "SELECT"},
	} {
		if r.pw == "" {
			continue
		}
		var exists bool
		if err := conn.QueryRow(ctx, "SELECT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = $1)", r.name).Scan(&exists); err != nil {
			return err
		}
		verb := "CREATE"
		if exists {
			verb = "ALTER"
		}
		var stmt string
		if err := conn.QueryRow(ctx, "SELECT format('"+verb+" ROLE %I LOGIN PASSWORD %L', $1::text, $2::text)", r.name, r.pw).Scan(&stmt); err != nil {
			return err
		}
		if _, err := conn.Exec(ctx, stmt); err != nil {
			return fmt.Errorf("role %s: %w", r.name, err)
		}
		for _, s := range []string{
			fmt.Sprintf("REVOKE ALL ON audit_events FROM %s", r.name),
			fmt.Sprintf("GRANT %s ON audit_events TO %s", r.grants, r.name),
			fmt.Sprintf("GRANT USAGE ON SCHEMA public TO %s", r.name),
		} {
			if _, err := conn.Exec(ctx, s); err != nil {
				return fmt.Errorf("%s: %w", s, err)
			}
		}
	}
	return nil
}

// ---------------------------------------------------------------- checkpoints

// Checkpoint is a signed statement of a chain head, published to a Kafka
// topic outside the database's trust domain.
type Checkpoint struct {
	ChainID     int32  `json:"chain_id"`
	Seq         int64  `json:"seq"`
	Hash        string `json:"hash"`
	KafkaOffset int64  `json:"kafka_offset"`
	TS          string `json:"ts"`
	Signature   string `json:"sig,omitempty"`
}

func (c *Checkpoint) signedBytes() []byte {
	return []byte(fmt.Sprintf("agentgate-checkpoint-v1|%d|%d|%s|%d|%s", c.ChainID, c.Seq, c.Hash, c.KafkaOffset, c.TS))
}

func (c *Checkpoint) Sign(key ed25519.PrivateKey) {
	c.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(key, c.signedBytes()))
}

func (c *Checkpoint) Verify(pub ed25519.PublicKey) bool {
	sig, err := base64.StdEncoding.DecodeString(c.Signature)
	return err == nil && ed25519.Verify(pub, c.signedBytes(), sig)
}

// ParsePrivateKey accepts a base64 32-byte seed or 64-byte private key.
func ParsePrivateKey(s string) (ed25519.PrivateKey, error) {
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil, err
	}
	switch len(b) {
	case ed25519.SeedSize:
		return ed25519.NewKeyFromSeed(b), nil
	case ed25519.PrivateKeySize:
		return ed25519.PrivateKey(b), nil
	}
	return nil, fmt.Errorf("signing key must be %d or %d bytes, got %d", ed25519.SeedSize, ed25519.PrivateKeySize, len(b))
}

func ParsePublicKey(s string) (ed25519.PublicKey, error) {
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil, err
	}
	if len(b) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("public key must be %d bytes", ed25519.PublicKeySize)
	}
	return ed25519.PublicKey(b), nil
}

func hexHash(b []byte) string { return hex.EncodeToString(b) }
