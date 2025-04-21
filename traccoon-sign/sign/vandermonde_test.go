package sign

import (
	"math/rand"
	"time"
	"traccoon-sign/utils"

	"testing"

	"github.com/tuneinsight/lattigo/v5/ring"
	"github.com/tuneinsight/lattigo/v5/utils/sampling"
	"github.com/tuneinsight/lattigo/v5/utils/structs"
)

// ============== Helper functions for testing ==============

func recover(r *ring.Ring, D ShareMap, R IndexMap) structs.Vector[ring.Poly] {
	res := utils.InitializeVector(r, DimEll)
	for usr, index := range R {
		utils.VectorAdd(r, D[usr][index], res, res) // Process each index
	}
	return res
}

// Function to sample a subset of T elements from an array
func sampleSubset(arr []int, T int) []int {
	// Initialize a map to track selected elements
	selected := make(map[int]bool)
	result := make([]int, 0, T)

	// Seed the random number generator
	rand.Seed(time.Now().UnixNano())

	// Keep sampling until we have T unique elements
	for len(result) < T {
		// Randomly select an index
		index := rand.Intn(len(arr))
		// If the element at this index hasn't been selected, add it to the result
		if !selected[index] {
			selected[index] = true
			result = append(result, arr[index])
		}
	}

	return result
}

func TestVandermondeRecover(t *testing.T) {
	NBOUND := 32
	for N := 2; N < NBOUND; N++ {
		T := N >> 1
		T++
		// Uncomment the following line to more extensive testing
		// for T := 1; T < N; T++ {
		r, _ := ring.NewRing(1<<5, []uint64{12889})

		prng, _ := sampling.NewKeyedPRNG([]byte("test"))
		gaussianParams := ring.DiscreteGaussian{Sigma: 1, Bound: 300}
		gaussianSampler := ring.NewGaussianSampler(prng, r, gaussianParams, false)

		// The parties are a vector of integers [0, 1, ... , N-1]
		P := make([]int, N)
		for i := 0; i < N; i++ {
			P[i] = i
		}
		// x := utils.SamplePolyVector(r, DimEll+DimK, gaussianSampler, false, false)
		x := utils.InitializeVector(r, DimEll)
		D := Share(r, gaussianSampler, x, P, T, "")
		var NBITER = 20
		for i := 0; i < NBITER; i++ {
			act := sampleSubset(P, T)
			recover_indeces := Recover(act, P, "")
			res := recover(r, D, recover_indeces)
			for i := range x {
				if !x[i].Equal(&res[i]) {
					t.Errorf("Recovered vector does not match original vector")
				}
			}
		}
		// }
	}
}
