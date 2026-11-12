package audit

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"testing"
)

func TestLinkHashBindsEveryInput(t *testing.T) {
	base := LinkHash(GenesisHash, 1, 7, []byte(`{"verdict":"block"}`))
	variants := [][]byte{
		LinkHash(GenesisHash, 2, 7, []byte(`{"verdict":"block"}`)),                 // other chain
		LinkHash(GenesisHash, 1, 8, []byte(`{"verdict":"block"}`)),                 // other position
		LinkHash(GenesisHash, 1, 7, []byte(`{"verdict":"allow"}`)),                 // edited content
		LinkHash(bytes.Repeat([]byte{1}, 32), 1, 7, []byte(`{"verdict":"block"}`)), // other history
	}
	for i, v := range variants {
		if bytes.Equal(v, base) {
			t.Fatalf("variant %d collides with base", i)
		}
	}
	if !bytes.Equal(base, LinkHash(GenesisHash, 1, 7, []byte(`{"verdict":"block"}`))) {
		t.Fatal("LinkHash is not deterministic")
	}
}

func TestCheckpointSignature(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	c := Checkpoint{ChainID: 0, Seq: 1000, Hash: "ab", KafkaOffset: 999, TS: "2026-11-04T00:00:00Z"}
	c.Sign(priv)
	if !c.Verify(pub) {
		t.Fatal("valid checkpoint rejected")
	}
	c.Hash = "cd"
	if c.Verify(pub) {
		t.Fatal("altered checkpoint accepted")
	}
}
