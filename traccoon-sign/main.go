package main

import (
	"bufio"
	"fmt"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
	"traccoon-sign/networking"
	"traccoon-sign/sign"

	"github.com/tuneinsight/lattigo/v5/ring"
	"github.com/tuneinsight/lattigo/v5/utils/structs"
)

func main() {

	if len(os.Args) < 2 {
		fmt.Println("Usage: go run main.go type= iter= t= n=")
		os.Exit(1)
	}

	if len(os.Args) > 5 {
		fmt.Println("Only four args are allowed")
		os.Exit(1)
	}

	args := make(map[string]string)
	for _, arg := range os.Args[1:] {
		parts := strings.SplitN(arg, "=", 2)
		if len(parts) != 2 {
			fmt.Printf("Invalid argument format: %s\n", arg)
			os.Exit(1)
		}
		args[parts[0]] = parts[1]
	}

	partyIDStr, ok := args["type"]
	if !ok {
		fmt.Println("Missing type parameter.")
		os.Exit(1)
	}

	iterStr, ok := args["iter"]
	if !ok {
		fmt.Println("Missing iter parameter.")
		os.Exit(1)
	}

	t, ok := args["t"]
	if !ok {
		fmt.Println("Missing t parameter.")
		os.Exit(1)
	}

	n, ok := args["n"]
	if !ok {
		fmt.Println("Missing n parameter.")
		os.Exit(1)
	}

	var err error
	var iters, threshold, parties int
	iters, err = strconv.Atoi(iterStr)
	threshold, err = strconv.Atoi(t)
	parties, err = strconv.Atoi(n)
	if err != nil {
		fmt.Println("Error: Please enter a valid integer for params.")
		os.Exit(1)
	}

	sign.K = parties
	sign.Threshold = threshold

	if partyIDStr == "d" {
		sign.LocalRun(iters)
		return
	}

	partyID, err := strconv.Atoi(partyIDStr)
	if err != nil {
		fmt.Println("Error: Please enter a valid integer.")
		os.Exit(1)
	}

	// Initialize P2P communication
	comm := &networking.P2PComm{
		Socks: make(map[int]*net.Conn),
		Rank:  partyID,
	}

	// Establish connections
	fmt.Println("Establishing connections...")
	var connWg sync.WaitGroup
	connWg.Add(1)
	go networking.EstablishConnections(&connWg, comm, partyID, sign.K)
	connWg.Wait()

	var setupDuration, genDuration, signRound1Duration, signRound2Duration, signRound3Duration, finalizeDuration, verifyDuration time.Duration
	var genStart, genEnd, signRound1Start, signRound1End, signRound2Start, signRound2End, signRound3Start, signRound3End, combinerReceiveEnd, combinerFinalizeEnd time.Time
	var A structs.Matrix[ring.Poly]
	var b structs.Vector[ring.Poly]

	// Variables to be used in SIGNATURE ROUNDS
	msgs1 := make(map[int][]byte)
	mu := "Message"
	T := make([]int, sign.K)
	for i := 0; i < sign.K; i++ {
		T[i] = i
	}

	fmt.Println("Generating secret shares...")
	var pk *sign.PublicKey
	var sk *sign.PrivateKey
	// Trusted dealer
	if partyID == sign.TrustedDealerID {
		// GEN: Generate secret shares, seeds, and MAC keys
		start := time.Now()
		pk, sks, err := sign.NewThresholdKeys(sign.Threshold, sign.K)
		sk = &sks[partyID]
		if err != nil {
			panic(err)
		}

		b = pk.Btilde
		A = pk.A
		genDuration = time.Since(start)
		genStart = time.Now()

		// Send out public information & trusted dealer data
		var sendWg sync.WaitGroup
		for i := 0; i < sign.K; i++ {
			if i != sign.TrustedDealerID {
				sendWg.Add(1)
				go func(i int) {
					defer sendWg.Done()
					writer := bufio.NewWriter(*comm.GetSock(i))
					comm.SendVector(writer, i, b)
					comm.SendMatrix(writer, i, A)
					// TODO: send vandermonde shares
				}(i)
			}
		}
		sendWg.Wait()
		genEnd = time.Now()
	} else {
		reader := bufio.NewReader(*comm.GetSock(sign.TrustedDealerID))
		b = comm.RecvVector(reader, sign.TrustedDealerID, sign.DimK)
		A = comm.RecvMatrix(reader, sign.TrustedDealerID, sign.DimK)
	}

	// Create your own party
	party := sign.NewParty(partyID, pk) // TODO: update

	time.Sleep(time.Second * 5)
	// SIGNATURE ROUND 1
	fmt.Printf("Timestamp before Sign Round 1 compute: %s\n", time.Now().Format("15:04:05.000000"))
	start := time.Now()
	var strd1 sign.StRound1
	msgs1[partyID], strd1 = party.SignRound1(pk)
	signRound1Duration = time.Since(start)
	log.Println("Completed R1")

	signRound1Start = time.Now()
	// Concurrently send and receive data
	var round1Wg sync.WaitGroup
	for i := 0; i < sign.K; i++ {
		if i != partyID {
			round1Wg.Add(2)
			go func(i int) {
				defer round1Wg.Done()
				writer := bufio.NewWriter(*comm.GetSock(i))
				comm.SendBytes(writer, i, msgs1[partyID])
			}(i)

			go func(i int) {
				defer round1Wg.Done()
				reader := bufio.NewReader(*comm.GetSock(i))
				msgs1[i], _, err = comm.Recv(reader, i)
			}(i)
		}
	}
	round1Wg.Wait()
	signRound1End = time.Now()

	// SIGN ROUND 2
	msgs2 := make(map[int][]byte)
	var strd2 sign.StRound2

	fmt.Printf("Timestamp before Sign Round 2 compute: %s\n", time.Now().Format("15:04:05.000000"))
	start = time.Now()
	msgs2[partyID], strd2 = party.SignRound2(pk, msgs1, strd1, mu, T)
	signRound2Duration = time.Since(start)

	signRound2Start = time.Now()
	// Concurrently send and receive data
	var round2Wg sync.WaitGroup
	for i := 0; i < sign.K; i++ {
		if i != partyID {
			round2Wg.Add(2)
			go func(i int) {
				defer round2Wg.Done()
				writer := bufio.NewWriter(*comm.GetSock(i))
				comm.SendBytes(writer, i, msgs2[partyID])
			}(i)

			go func(i int) {
				defer round2Wg.Done()
				reader := bufio.NewReader(*comm.GetSock(i))
				msgs2[i], _, err = comm.Recv(reader, i)
			}(i)
		}
	}
	round2Wg.Wait()
	signRound2End = time.Now()

	// SIGN ROUND 3
	msgs3 := make(map[int][]byte)

	fmt.Printf("Timestamp before Sign Round 3 compute: %s\n", time.Now().Format("15:04:05.000000"))
	start = time.Now()
	ok, msgs3[partyID] = party.SignRound3(pk, sk, msgs2, strd2, mu, T, sign.K)
	if !ok {
		panic("Hash mismatch")
	}
	signRound3Duration = time.Since(start)

	signRound3Start = time.Now()
	if partyID != sign.CombinerID {
		writer := bufio.NewWriter(*comm.GetSock(sign.CombinerID))
		comm.SendBytes(writer, sign.CombinerID, msgs3[partyID])
		signRound3End = time.Now()
	} else {
		for i := 0; i < sign.K; i++ {
			if i != sign.CombinerID {
				reader := bufio.NewReader(*comm.GetSock(i))
				msgs3[i], _, err = comm.Recv(reader, i)
			}
		}
		combinerReceiveEnd = time.Now()

		fmt.Printf("Timestamp before Finalize: %s\n", time.Now().Format("15:04:05.000000"))
		// SIGNATURE FINALIZE
		start := time.Now()
		c, sig, Delta := party.SignFinalize(pk, msgs2, msgs3, mu)
		finalizeDuration = time.Since(start)
		combinerFinalizeEnd = time.Now()
		// Verify the signature
		start = time.Now()
		verified := sign.Verify(pk, sig, mu, c, Delta)
		verifyDuration = time.Since(start)
		fmt.Printf("Signature Verification Result: %v\n", verified)
	}

	// Print all durations
	fmt.Println("Setup duration:", setupDuration)
	fmt.Println("Gen duration:", genDuration)
	fmt.Println("Signature Round 1 duration:", signRound1Duration)
	fmt.Println("Signature Round 2 duration:", signRound2Duration)
	fmt.Println("Signature Round 3 duration:", signRound3Duration)
	fmt.Println("Finalize duration:", finalizeDuration)
	fmt.Println("Verify duration:", verifyDuration)

	// Print timestamps for networking
	fmt.Printf("Gen start timestamp: %s\n", genStart.Format("15:04:05.000000"))
	fmt.Printf("Gen end timestamp: %s\n", genEnd.Format("15:04:05.000000"))

	fmt.Printf("Sign Round 1 sending/receiving start timestamp: %s\n", signRound1Start.Format("15:04:05.000000"))
	fmt.Printf("Sign Round 1 sending/receiving end timestamp: %s\n", signRound1End.Format("15:04:05.000000"))

	fmt.Printf("Sign Round 2 sending/receiving start timestamp: %s\n", signRound2Start.Format("15:04:05.000000"))
	fmt.Printf("Sign Round 2 sending end timestamp: %s\n", signRound2End.Format("15:04:05.000000"))

	fmt.Printf("Sign Round 3 sending/receiving start timestamp: %s\n", signRound3Start.Format("15:04:05.000000"))
	fmt.Printf("Sign Round 3 sending end timestamp: %s\n", signRound3End.Format("15:04:05.000000"))

	if partyID == sign.CombinerID {
		fmt.Printf("Combiner receive end timestamp: %s\n", combinerReceiveEnd.Format("15:04:05.000000"))
		fmt.Printf("Combiner finalize end timestamp: %s\n", combinerFinalizeEnd.Format("15:04:05.000000"))
	}
}
