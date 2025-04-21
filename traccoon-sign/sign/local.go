package sign

import (
	"fmt"
	"log"
	"time"

	"github.com/montanaflynn/stats"
)

var K int
var Threshold int

// Main function orchestrates the threshold signature protocol
func LocalRun(x int) {
	var totalGenDuration, totalFinalizeDuration, totalVerifyDuration time.Duration

	// Create maps to collect durations across all runs
	totalSignRound1Durations := make(map[int]float64)
	totalSignRound2Durations := make(map[int]float64)
	totalSignRound3Durations := make(map[int]float64)

	for run := 0; run < x; run++ {
		log.Println("RUN:", run)
		var genDuration, finalizeDuration, verifyDuration time.Duration

		log.Println("Gen")
		start := time.Now()
		pk, sks, err := NewThresholdKeys(Threshold, K)
		if err != nil {
			panic(err)
		}

		parties := make([]*Party, K)
		for i := range parties {
			parties[i] = NewParty(i, pk)
		}
		genDuration = time.Since(start)
		log.Println("Gen Duration:", genDuration)

		// Set of signers
		T := make([]int, Threshold) // Active parties
		for i := 0; i < Threshold; i++ {
			T[i] = i
		}

		// Create maps to collect durations for this run
		signRound1Durations := make(map[int]time.Duration)
		signRound2Durations := make(map[int]time.Duration)
		signRound3Durations := make(map[int]time.Duration)

		// SIGNATURE ROUND 1
		mu := "Message"
		msgs1 := make(map[int][]byte)
		strd1 := make(map[int]StRound1)
		for _, partyID := range T {
			log.Println("Sign Round 1, party", partyID)
			start = time.Now()
			msgs1[partyID], strd1[partyID] = parties[partyID].SignRound1(pk)
			fmt.Printf("[DEBUG] Size of msgs1[%d]: %d bytes\n", partyID, len(msgs1[partyID]))
			signRound1Durations[partyID] = time.Since(start)
		}

		// SIGNATURE ROUND 2
		msgs2 := make(map[int][]byte)
		strd2 := make(map[int]StRound2)

		for _, partyID := range T {
			log.Println("Sign round 2 party", partyID)
			start = time.Now()
			msgs2[partyID], strd2[partyID] = parties[partyID].SignRound2(pk, msgs1, strd1[partyID], mu, T)
			fmt.Printf("[DEBUG] Size of msgs2[%d]: %d bytes\n", partyID, len(msgs2[partyID]))
			signRound2Durations[partyID] = time.Since(start)
		}

		// SIGNATURE ROUND 3
		msgs3 := make(map[int][]byte)

		for _, partyID := range T {
			log.Println("Sign round 3 party", partyID)
			start = time.Now()
			var ok bool
			ok, msgs3[partyID] = parties[partyID].SignRound3(pk, &sks[partyID], msgs2, strd2[partyID], mu, T, K)
			fmt.Printf("[DEBUG] Size of msgs3[%d]: %d bytes\n", partyID, len(msgs3[partyID]))
			if !ok {
				panic("Hash mismatch")
			}
			signRound3Durations[partyID] = time.Since(start)
		}

		// SIGNATURE FINALIZE
		log.Println("finalizing...")
		finalParty := parties[0]
		start = time.Now()
		c, sig, Delta := finalParty.SignFinalize(pk, msgs2, msgs3, mu)
		finalizeDuration = time.Since(start)

		// Verify the signature
		start = time.Now()
		valid := Verify(pk, sig, mu, c, Delta)
		verifyDuration = time.Since(start)
		fmt.Printf("Signature Verification Result: %v\n", valid)

		// Accumulate durations
		totalGenDuration += genDuration
		totalFinalizeDuration += finalizeDuration
		totalVerifyDuration += verifyDuration

		// Accumulate phase durations
		for partyID, duration := range signRound1Durations {
			totalSignRound1Durations[partyID] += float64(duration.Nanoseconds()) / 1e6
		}
		for partyID, duration := range signRound2Durations {
			totalSignRound2Durations[partyID] += float64(duration.Nanoseconds()) / 1e6
		}
		for partyID, duration := range signRound3Durations {
			totalSignRound3Durations[partyID] += float64(duration.Nanoseconds()) / 1e6
		}
	}

	// Print averaged durations
	fmt.Println("Averaged durations over", x, "runs:")
	fmt.Printf("Gen duration: %.3f ms\n", float64(totalGenDuration.Nanoseconds())/1e6/float64(x))
	fmt.Printf("Finalize duration: %.3f ms\n", float64(totalFinalizeDuration.Nanoseconds())/1e6/float64(x))
	fmt.Printf("Verify duration: %.3f ms\n", float64(totalVerifyDuration.Nanoseconds())/1e6/float64(x))

	// Calculate and print averaged statistics for each phase
	printAveragedStats("Signature Round 1", totalSignRound1Durations, x)
	printAveragedStats("Signature Round 2", totalSignRound2Durations, x)
	printAveragedStats("Signature Round 3", totalSignRound3Durations, x)

	// Calculate and print total signing and offline durations
	totalSigningDurations := make(map[int]float64)
	for partyID := range totalSignRound1Durations {
		totalSigningDurations[partyID] = totalSignRound1Durations[partyID] + totalSignRound2Durations[partyID] + totalSignRound3Durations[partyID] + float64(totalFinalizeDuration.Nanoseconds())/1e6/float64(x)
	}
	printAveragedStats("Total Signing", totalSigningDurations, x)
}

// printAveragedStats prints the mean, median, and standard deviation for a map of durations averaged over x runs
func printAveragedStats(phaseName string, totalDurations map[int]float64, x int) {
	var values []float64
	for _, totalDuration := range totalDurations {
		values = append(values, totalDuration/float64(x))
	}
	mean, _ := stats.Mean(values)
	median, _ := stats.Median(values)
	stddev, _ := stats.StandardDeviation(values)

	fmt.Printf("%s averaged duration stats over %d runs:\n", phaseName, x)
	fmt.Printf("  Mean: %.3f ms\n", mean)
	fmt.Printf("  Median: %.3f ms\n", median)
	fmt.Printf("  Standard Deviation: %.3f ms\n", stddev)
}
