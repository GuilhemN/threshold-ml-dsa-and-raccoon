package sign

import (
	"fmt"
	"math/bits"
	"sort"
	"traccoon-sign/utils"

	"github.com/tuneinsight/lattigo/v5/ring"
	"github.com/tuneinsight/lattigo/v5/utils/structs"
)

type ShareMap map[int]map[string]structs.Vector[ring.Poly]
type IndexMap map[int]string

/*
The Share function takes a vector x, a list of parties P, a threshold T and an index idx
It returns a map D where D[user][index] is the share of user user for index index
(as in the Python version)

The Recover function takes a list of active parties act, a list of parties P and an index idx
It returns a map R where R[user] is the index of user user
(as in the Python version)

TODO: Implement the special sharings for 2, 3 and N parties
*/

func share_n(r *ring.Ring, sampler *ring.GaussianSampler, x structs.Vector[ring.Poly], P []int, idx string) ShareMap {
	// Ensure all user indices are contiguous
	minP := P[0]
	maxP := P[len(P)-1]

	if maxP-minP+1 != len(P) {
		panic("User indices must be contiguous")
	}

	D := make(ShareMap)
	for _, user := range P {
		D[user] = make(map[string]structs.Vector[ring.Poly])
	}

	newIdx := idx + "N:"
	S := utils.InitializeVector(r, DimEll)

	for _, user := range P {
		if user == minP {
			continue
		}
		userIdx := fmt.Sprintf("%s%d", newIdx, user-minP)
		D[user][userIdx] = utils.SamplePolyVector(r, DimEll, sampler, false, false)
		utils.VectorAdd(r, S, D[user][userIdx], S)
	}

	zeroIdx := fmt.Sprintf("%s%d", newIdx, 0)
	D[minP][zeroIdx] = utils.InitializeVector(r, DimEll)
	utils.VectorSub(r, x, S, D[minP][zeroIdx])

	return D
}

func recover_n(act, P []int, idx string) IndexMap {
	if len(P) != len(act) {
		panic("All active users must be present in P")
	}

	newIdx := idx + "N:"
	result := make(IndexMap)
	minAct := act[0]

	for _, user := range act {
		result[user] = fmt.Sprintf("%s%d", newIdx, user-minAct)
	}

	return result
}

func share_2(r *ring.Ring, sampler *ring.GaussianSampler, x structs.Vector[ring.Poly], P []int, idx string) ShareMap {
	minP := P[0]
	maxP := P[len(P)-1]
	if maxP-minP+1 != len(P) {
		panic("User indices must be contiguous")
	}

	n := bits.Len(uint(len(P) - 1))
	D := make(ShareMap)
	for _, user := range P {
		D[user] = make(map[string]structs.Vector[ring.Poly])
	}

	newIdx := idx + "B:"

	for i := 0; i < n; i++ {
		x0 := utils.SamplePolyVector(r, DimEll, sampler, false, false)
		x1 := utils.InitializeVector(r, DimEll)
		utils.VectorSub(r, x, x0, x1)
		y := [2]structs.Vector[ring.Poly]{x0, x1}
		for _, user := range P {
			u := ((user - minP) >> i) % 2
			userIdx := fmt.Sprintf("%s%d:%d", newIdx, i, u)
			D[user][userIdx] = y[u]
		}
	}

	return D
}

func recover_2(act, P []int, idx string) map[int]string {
	newIdx := idx + "B:"
	user0, user1 := act[0], act[len(act)-1]
	i := 0
	v0 := user0 - P[0]
	v1 := user1 - P[0]

	for ((v0^v1)>>i)%2 == 0 {
		i++
	}

	u0 := (v0 >> i) % 2
	u1 := (v1 >> i) % 2

	return map[int]string{
		user0: fmt.Sprintf("%s%d:%d", newIdx, i, u0),
		user1: fmt.Sprintf("%s%d:%d", newIdx, i, u1),
	}
}

func Share(r *ring.Ring, sampler *ring.GaussianSampler, x structs.Vector[ring.Poly], P []int, T int, idx string) ShareMap {
	N := len(P)
	D := make(ShareMap)
	for _, user := range P {
		D[user] = make(map[string]structs.Vector[ring.Poly])
	}

	if T == 1 {
		for _, user := range P {
			D[user][idx] = x
		}
		return D
	} else if T == N {
		return share_n(r, sampler, x, P, idx)
	} else if T == 2 {
		return share_2(r, sampler, x, P, idx)
	}

	c := N >> 1
	P_L := P[:c]
	P_R := P[c:]

	min_k := max(0, T-N+c)
	max_k := min(c, T)

	rec_D := []ShareMap{}
	for k := min_k; k <= max_k; k++ {
		idx_L := idx + "L|" + fmt.Sprint(k) + "|"
		idx_R := idx + "R|" + fmt.Sprint(T-k) + "|"
		if k == 0 {
			rec_D = append(rec_D, Share(r, sampler, x, P_R, T, idx_R))
		} else if k == T {
			rec_D = append(rec_D, Share(r, sampler, x, P_L, T, idx_L))
		} else {
			x0 := utils.SamplePolyVector(r, DimEll, sampler, false, false)
			x1 := utils.InitializeVector(r, DimEll)
			utils.VectorSub(r, x, x0, x1)
			rec_D = append(rec_D, Share(r, sampler, x0, P_L, k, idx_L))
			rec_D = append(rec_D, Share(r, sampler, x1, P_R, T-k, idx_R))
		}
	}

	for _, Dp := range rec_D {
		for user, data := range Dp {
			for key, value := range data {
				D[user][key] = value
			}
		}
	}

	return D
}

func Recover(act, P []int, idx string) IndexMap {
	/*
		Recover takes a list of active parties act, a list of parties P and an index
		idx It returns a map R where R[user] is the index of user user

		Note: the function assumes that the user indices in P are contiguous and
		sorts the acting users act.
	*/
	T := len(act)
	// Sort the result to maintain order
	if !sort.IntsAreSorted(act) {
		sort.Ints(act)
	}
	N := len(P)

	if T == 1 {
		result := make(IndexMap)
		for _, user := range act {
			result[user] = idx
		}
		return result
	} else if T == N {
		return recover_n(act, P, idx)
	} else if T == 2 {
		return recover_2(act, P, idx)
	}

	c := N >> 1
	P_L := P[:c]
	P_R := P[c:]

	act_L := intersection(act, P_L)
	act_R := intersection(act, P_R)

	k := len(act_L)
	idx_L := idx + fmt.Sprintf("L|%d|", k)
	idx_R := idx + fmt.Sprintf("R|%d|", T-k)

	if k == 0 {
		return Recover(act, P_R, idx_R)
	} else if k == T {
		return Recover(act, P_L, idx_L)
	} else {
		rep := Recover(act_L, P_L, idx_L)
		for key, value := range Recover(act_R, P_R, idx_R) {
			rep[key] = value
		}
		return rep
	}
}

func intersection(a, b []int) []int {
	set := make(map[int]bool)
	for _, item := range b {
		set[item] = true
	}
	var result []int
	for _, item := range a {
		if set[item] {
			result = append(result, item)
		}
	}
	return result
}
