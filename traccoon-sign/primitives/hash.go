package primitives

import (
	"bytes"
	"encoding/binary"
	"log"

	"github.com/tuneinsight/lattigo/v5/ring"
	"github.com/tuneinsight/lattigo/v5/utils/sampling"
	"github.com/tuneinsight/lattigo/v5/utils/structs"
	"github.com/zeebo/blake3"
)

const keySize = 32

// Hashes a commitment
func HashCommitment(A structs.Matrix[ring.Poly], b structs.Vector[ring.Poly], w structs.Vector[ring.Poly], partyID int) []byte {
	hasher := blake3.New()
	buf := new(bytes.Buffer)

	if _, err := A.WriteTo(buf); err != nil {
		log.Fatalf("Error writing matrix A: %v\n", err)
	}

	if _, err := b.WriteTo(buf); err != nil {
		log.Fatalf("Error writing vector b: %v\n", err)
	}

	if _, err := w.WriteTo(buf); err != nil {
		log.Fatalf("Error writing vector w: %v\n", err)
	}

	binary.Write(buf, binary.BigEndian, int64(partyID))

	hasher.Write(buf.Bytes())
	hashOutput := hasher.Sum(nil)
	return hashOutput[:keySize]
}

// Hashes precomputable values
func Hash(A structs.Matrix[ring.Poly], b structs.Vector[ring.Poly], D map[int]structs.Vector[ring.Poly], sid int, T []int) []byte {
	hasher := blake3.New()
	buf := new(bytes.Buffer)

	if _, err := A.WriteTo(buf); err != nil {
		log.Fatalf("Error writing matrix A: %v\n", err)
	}

	if _, err := b.WriteTo(buf); err != nil {
		log.Fatalf("Error writing vector b: %v\n", err)
	}

	binary.Write(buf, binary.BigEndian, int64(sid))
	binary.Write(buf, binary.BigEndian, T)

	for i := 0; i < len(D); i++ {
		if _, err := D[i].WriteTo(buf); err != nil {
			log.Fatalf("Error writing vector D_i: %v\n", err)
		}
	}

	hasher.Write(buf.Bytes())
	hashOutput := hasher.Sum(nil)
	return hashOutput[:keySize]
}

// Hashes to low norm ring elements
func LowNormHash(r *ring.Ring, A structs.Matrix[ring.Poly], b structs.Vector[ring.Poly], h structs.Vector[ring.Poly], mu string, kappa int) ring.Poly {
	hasher := blake3.New()
	buf := new(bytes.Buffer)

	if _, err := A.WriteTo(buf); err != nil {
		log.Fatalf("Error writing matrix A: %v\n", err)
	}

	if _, err := b.WriteTo(buf); err != nil {
		log.Fatalf("Error writing vector b: %v\n", err)
	}

	if _, err := h.WriteTo(buf); err != nil {
		log.Fatalf("Error writing vector h: %v\n", err)
	}

	binary.Write(buf, binary.BigEndian, []byte(mu))

	hasher.Write(buf.Bytes())
	hashOutput := hasher.Sum(nil)

	prng, _ := sampling.NewKeyedPRNG(hashOutput[:keySize])
	ternaryParams := ring.Ternary{H: kappa}
	ternarySampler, err := ring.NewTernarySampler(prng, r, ternaryParams, false)
	if err != nil {
		log.Fatalf("Error creating ternary sampler: %v", err)
	}
	c := ternarySampler.ReadNew()
	r.NTT(c, c)
	r.MForm(c, c)

	return c
}