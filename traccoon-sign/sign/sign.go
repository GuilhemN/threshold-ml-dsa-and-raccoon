package sign

import (
	"bytes"
	"errors"
	"log"
	"math/big"
	"traccoon-sign/primitives"
	"traccoon-sign/utils"

	"github.com/tuneinsight/lattigo/v5/ring"
	"github.com/tuneinsight/lattigo/v5/utils/sampling"
	"github.com/tuneinsight/lattigo/v5/utils/structs"
)

type PublicKey struct {
	Ring   *ring.Ring
	RingXi *ring.Ring
	RingNu *ring.Ring
	A      structs.Matrix[ring.Poly]
	Btilde structs.Vector[ring.Poly]
}

type PrivateKey struct {
	ID     int
	Shares map[string]structs.Vector[ring.Poly]
}

// Party struct holds all state and methods for a party in the protocol
type Party struct {
	ID int
}

type StRound1 struct {
	W     structs.Vector[ring.Poly]
	Rstar structs.Vector[ring.Poly]
}
type StRound2 struct {
	Hashes map[int][]byte
	Act    []int
	Rstar  structs.Vector[ring.Poly]
}

// NewParty initializes a new Party instance
func NewParty(id int, pk *PublicKey) *Party {
	return &Party{
		ID: id,
	}
}

func NewThresholdKeys(T, N int) (*PublicKey, []PrivateKey, error) {
	if T == 0 || T > N {
		return nil, nil, errors.New("Invalid threshold parameters")
	}
	r, _ := ring.NewRing(1<<LogN, []uint64{Q})
	r_xi, _ := ring.NewRing(1<<LogN, []uint64{QXi})
	r_nu, _ := ring.NewRing(1<<LogN, []uint64{QNu})

	prng, _ := sampling.NewPRNG()
	uniformSampler := ring.NewUniformSampler(prng, r)

	A := utils.SamplePolyMatrix(r, DimK, DimEll, uniformSampler, true, true)

	pk := PublicKey{
		Ring:   r,
		RingXi: r_xi,
		RingNu: r_nu,
		A:      A,
	}

	gaussianParams := ring.DiscreteGaussian{Sigma: SigmaE, Bound: BoundE}
	gaussianSampler := ring.NewGaussianSampler(prng, r, gaussianParams, false)

	// Sample a secret
	s := utils.SamplePolyVector(r, DimEll, gaussianSampler, false, false)

	// Generate a Vandermonde sharing of s
	// The parties are a vector of integers [0, 1, ... , N-1]
	P := make([]int, N)
	for i := 0; i < N; i++ {
		P[i] = i
	}

	s_copy := utils.InitializeVector(r, DimEll)
	utils.VectorAdd(r, s, s_copy, s_copy)
	shares := Share(r, gaussianSampler, s_copy, P, T, "")

	// Sample e and compute the public key b = A*s + e
	utils.ConvertVectorToNTT(r, s)

	e := utils.SamplePolyVector(r, DimK, gaussianSampler, true, true)
	b := utils.InitializeVector(r, DimK)
	utils.MatrixVectorMul(r, A, s, b)
	utils.VectorAdd(r, b, e, b)

	// Round b
	utils.ConvertVectorFromNTT(r, b)
	pk.Btilde = utils.RoundVector(r, r_xi, b, Xi)

	sks := make([]PrivateKey, N)
	for partyID := 0; partyID < N; partyID++ {
		sks[partyID] = PrivateKey{
			ID:     partyID,
			Shares: shares[partyID],
		}
	}

	return &pk, sks, nil
}

// SignRound1 performs the first round of signing
func (party *Party) SignRound1(pk *PublicKey) ([]byte, StRound1) {
	r := pk.Ring

	// Initialize r_star and e_star
	prng, _ := sampling.NewPRNG()
	gaussianParams := ring.DiscreteGaussian{Sigma: SigmaStar, Bound: BoundStar}
	gaussianSampler := ring.NewGaussianSampler(prng, r, gaussianParams, false)
	r_star := utils.SamplePolyVector(r, DimEll, gaussianSampler, true, true)
	e_star := utils.SamplePolyVector(r, DimK, gaussianSampler, true, true)

	w := utils.InitializeVector(r, DimK)

	utils.MatrixVectorMul(r, pk.A, r_star, w)
	utils.VectorAdd(r, e_star, w, w)

	utils.ConvertVectorFromNTT(r, w)

	// Hash the commitment
	return primitives.HashCommitment(pk.A, pk.Btilde, w, party.ID), StRound1{w, r_star}
}

// SignRound2 performs the second round of signing
func (party *Party) SignRound2(pk *PublicKey, msgs1 map[int][]byte, strd1 StRound1, mu string, T []int) ([]byte, StRound2) {
	buf := new(bytes.Buffer)
	if _, err := strd1.W.WriteTo(buf); err != nil {
		log.Fatalf("Error writing vector w: %v\n", err)
	}

	return buf.Bytes(), StRound2{msgs1, T, strd1.Rstar}
}

// SignRound2 performs the second round of signing
func (party *Party) SignRound3(pk *PublicKey, sk *PrivateKey, msgs2 map[int][]byte, strd2 StRound2, mu string, T []int, K int) (bool, []byte) {
	if len(msgs2) != len(strd2.Hashes) {
		return false, nil
	}

	ws := make(map[int]structs.Vector[ring.Poly])
	for ID, buf := range msgs2 {
		w := make(structs.Vector[ring.Poly], DimK)
		if _, err := w.ReadFrom(bytes.NewReader(buf)); err != nil {
			log.Fatalf("Failed to read vector: %v", err)
		}
		ws[ID] = w
	}

	for ID, hash := range strd2.Hashes {
		if !bytes.Equal(hash, primitives.HashCommitment(pk.A, pk.Btilde, ws[ID], ID)) {
			return false, nil
		}
	}
	r := pk.Ring
	r_nu := pk.RingNu

	h := utils.InitializeVector(r, DimK)
	for _, W_j := range ws {
		utils.VectorAdd(r, h, W_j, h)
	}

	roundedH := utils.RoundVector(r, r_nu, h, Nu)

	c := primitives.LowNormHash(r, pk.A, pk.Btilde, roundedH, mu, Kappa)

	// Initialize z_i to r_i
	z_i := utils.InitializeVector(r, DimEll)
	utils.VectorAdd(r, strd2.Rstar, z_i, z_i)

	// Compute s*c

	// The parties are a vector of integers [0, 1, ... , N-1]
	P := make([]int, K)
	for i := 0; i < K; i++ {
		P[i] = i
	}

	recover_indeces := Recover(T, P, "")

	s_c := utils.InitializeVector(r, DimEll)
	utils.VectorAdd(r, sk.Shares[recover_indeces[party.ID]], s_c, s_c)
	utils.ConvertVectorToNTT(r, s_c)
	utils.VectorPolyMul(r, s_c, c, s_c)
	utils.VectorAdd(r, z_i, s_c, z_i)

	buf := new(bytes.Buffer)
	if _, err := z_i.WriteTo(buf); err != nil {
		log.Fatalf("Error writing vector z: %v\n", err)
	}

	return true, buf.Bytes()
}

// SignFinalize finalizes the signature
func (party *Party) SignFinalize(pk *PublicKey, msgs2 map[int][]byte, msgs3 map[int][]byte, mu string) (ring.Poly, structs.Vector[ring.Poly], structs.Vector[ring.Poly]) {
	w_sum := utils.InitializeVector(pk.Ring, DimK)
	for _, buf := range msgs2 {
		w_j := make(structs.Vector[ring.Poly], DimK)
		if _, err := w_j.ReadFrom(bytes.NewReader(buf)); err != nil {
			log.Fatalf("Failed to read vector: %v", err)
		}
		utils.VectorAdd(pk.Ring, w_sum, w_j, w_sum)
	}

	roundedH := utils.RoundVector(pk.Ring, pk.RingNu, w_sum, Nu)
	c := primitives.LowNormHash(pk.Ring, pk.A, pk.Btilde, roundedH, mu, Kappa)

	z_sum := utils.InitializeVector(pk.Ring, DimEll)
	for _, buf := range msgs3 {
		z_j := make(structs.Vector[ring.Poly], DimEll)
		if _, err := z_j.ReadFrom(bytes.NewReader(buf)); err != nil {
			log.Fatalf("Failed to read vector: %v", err)
		}
		utils.VectorAdd(pk.Ring, z_sum, z_j, z_sum)
	}

	Az_bc := utils.InitializeVector(pk.Ring, DimK)
	utils.MatrixVectorMul(pk.Ring, pk.A, z_sum, Az_bc)
	bc := utils.InitializeVector(pk.Ring, DimK)

	b := utils.RestoreVector(pk.Ring, pk.RingXi, pk.Btilde, Xi)
	utils.ConvertVectorToNTT(pk.Ring, b)

	utils.VectorPolyMul(pk.Ring, b, c, bc)
	utils.VectorSub(pk.Ring, Az_bc, bc, Az_bc)

	utils.ConvertVectorFromNTT(pk.Ring, Az_bc)
	roundedAz_bc := utils.RoundVector(pk.Ring, pk.RingNu, Az_bc, Nu)

	Delta := utils.InitializeVector(pk.RingNu, DimK)
	utils.VectorSub(pk.RingNu, roundedH, roundedAz_bc, Delta)

	return c, z_sum, Delta
}

// Verify verifies the correctness of the signature
func Verify(pk *PublicKey, z structs.Vector[ring.Poly], mu string, c ring.Poly, roundedDelta structs.Vector[ring.Poly]) bool {
	Az_bc := utils.InitializeVector(pk.Ring, DimK)
	utils.MatrixVectorMul(pk.Ring, pk.A, z, Az_bc)
	bc := utils.InitializeVector(pk.Ring, DimK)

	b := utils.RestoreVector(pk.Ring, pk.RingXi, pk.Btilde, Xi)
	utils.ConvertVectorToNTT(pk.Ring, b)

	utils.VectorPolyMul(pk.Ring, b, c, bc)
	utils.VectorSub(pk.Ring, Az_bc, bc, Az_bc)

	utils.ConvertVectorFromNTT(pk.Ring, Az_bc)
	roundedAz_bc := utils.RoundVector(pk.Ring, pk.RingNu, Az_bc, Nu)

	Az_bc_Delta := utils.InitializeVector(pk.RingNu, DimK)
	utils.VectorAdd(pk.RingNu, roundedAz_bc, roundedDelta, Az_bc_Delta)

	computedC := primitives.LowNormHash(pk.Ring, pk.A, pk.Btilde, Az_bc_Delta, mu, Kappa)
	if !pk.Ring.Equal(c, computedC) {
		return false
	}

	Delta := utils.RestoreVector(pk.Ring, pk.RingNu, roundedDelta, Nu)
	utils.ConvertVectorFromNTT(pk.Ring, z)
	return CheckL2Norm(pk.Ring, Delta, z)
}

// CheckL2Norm checks if the L2 norm of the vector of Delta is less than or equal to Bsquare
func CheckL2Norm(r *ring.Ring, Delta structs.Vector[ring.Poly], z structs.Vector[ring.Poly]) bool {
	sumSquares := big.NewInt(0)
	qBig := new(big.Int).SetUint64(Q)
	halfQ := new(big.Int).Div(qBig, big.NewInt(2))

	DeltaCoeffsBigInt := make(structs.Vector[[]*big.Int], r.N())
	for i, polyCoeffs := range Delta {
		DeltaCoeffsBigInt[i] = make([]*big.Int, r.N())
		r.PolyToBigint(polyCoeffs, 1, DeltaCoeffsBigInt[i])
	}

	for _, polyCoeffs := range DeltaCoeffsBigInt {
		for _, coeff := range polyCoeffs {
			if coeff.Cmp(halfQ) > 0 {
				coeff.Sub(coeff, qBig)
			}
			coeffSquare := new(big.Int).Mul(coeff, coeff)
			sumSquares.Add(sumSquares, coeffSquare)
		}
	}

	zCoeffsBigInt := make(structs.Vector[[]*big.Int], r.N())
	for i, polyCoeffs := range z {
		zCoeffsBigInt[i] = make([]*big.Int, r.N())
		r.PolyToBigint(polyCoeffs, 1, zCoeffsBigInt[i])
	}

	for _, polyCoeffs := range zCoeffsBigInt {
		for _, coeff := range polyCoeffs {
			if coeff.Cmp(halfQ) > 0 {
				coeff.Sub(coeff, qBig)
			}
			coeffSquare := new(big.Int).Mul(coeff, coeff)
			sumSquares.Add(sumSquares, coeffSquare)
		}
	}

	log.Println("Sum of Squares:", sumSquares)
	log.Println("Bsquare:", Bsquare)

	Bsquare, _ := new(big.Int).SetString(Bsquare, 10)
	return sumSquares.Cmp(Bsquare) <= 0
}
