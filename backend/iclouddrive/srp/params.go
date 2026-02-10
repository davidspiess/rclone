package srp

import (
	"crypto"
	"fmt"
	"math/big"
)

func init() {
	knownGroups = make(map[int]*SRPParams)

	knownGroups[2048] = createParams(2, 2048, crypto.SHA256, `
		AC6BDB41 324A9A9B F166DE5E 1389582F AF72B665 1987EE07 FC319294
		3DB56050 A37329CB B4A099ED 8193E075 7767A13D D52312AB 4B03310D
		CD7F48A9 DA04FD50 E8083969 EDB767B0 CF609517 9A163AB3 661A05FB
		D5FAAAE8 2918A996 2F0B93B8 55F97993 EC975EEA A80D740A DBF4FF74
		7359D041 D5C33EA7 1D281E44 6B14773B CA97B43A 23FB8016 76BD207A
		436C6481 F1D2B907 8717461A 5B9D32E6 88F87748 544523B5 24B0D57D
		5EA77A27 75D2ECFA 032CFBDB F52FB378 61602790 04E57AE6 AF874E73
		03CE5329 9CCC041C 7BC308D8 2A5698F3 A8D0C382 71AE35F8 E9DBFBB6
		94B5C803 D89F7AE4 35DE236D 525F5475 9B65E372 FCD68EF2 0FA7111F
		9E4AFF73
	`)
}

// Map of bits to <g, N> tuple
type SRPParams struct {
	G             *big.Int
	N             *big.Int
	Hash          crypto.Hash
	NLengthBits   int
	NoUserNameInX bool
}

var knownGroups map[int]*SRPParams

func createParams(G int64, nBitLength int, hash crypto.Hash, NHex string) *SRPParams {
	p := SRPParams{
		G:           big.NewInt(G),
		N:           new(big.Int),
		NLengthBits: nBitLength,
		Hash:        hash,
	}

	b := bytesFromHexString(NHex)
	p.N.SetBytes(b)
	return &p
}

func GetParams(G int) *SRPParams {
	params := knownGroups[G]
	if params == nil {
		panic(fmt.Sprintf("Params don't exist for %v", G))
	} else {
		return params
	}
}

func (params *SRPParams) calculateA(a *big.Int) []byte {
	ANum := new(big.Int)
	ANum.Exp(params.G, a, params.N)
	return padToN(ANum, params)
}

func (params *SRPParams) calculateU(A, B *big.Int) *big.Int {
	hashU := params.Hash.New()
	ab := append(padToN(A, params), padToN(B, params)...)
	hashU.Write(ab)
	r := hashToInt(hashU)
	return r
}

// calculateS  /* Client Side S = (B - k*(g^x)) ^ (a + ux) */
func (params *SRPParams) calculateS(k, x, a, B, u *big.Int) []byte {
	BLessThan0 := B.Cmp(big.NewInt(0)) <= 0
	NLessThanB := params.N.Cmp(B) <= 0
	if BLessThan0 || NLessThanB {
		panic("invalid server-supplied 'B', must be 1..N-1")
	}
	result1 := new(big.Int)
	result1.Exp(params.G, x, params.N)

	result2 := new(big.Int)
	result2.Mul(k, result1)

	result3 := new(big.Int)
	result3.Sub(B, result2)

	result4 := new(big.Int)
	result4.Mul(u, x)

	result5 := new(big.Int)
	result5.Add(a, result4)

	result6 := new(big.Int)
	result6.Exp(result3, result5, params.N)

	result7 := new(big.Int)
	result7.Mod(result6, params.N)
	return padToN(result7, params)
}

func (params *SRPParams) calculateK(S []byte) []byte {
	hashK := params.Hash.New()
	hashK.Write(S)
	return hashToBytes(hashK)
}

// calculateX // x = SHA(s | SHA(U | ":" | p))
func (params *SRPParams) calculateX(salt, I, P []byte) *big.Int {
	h := params.Hash.New()
	if !params.NoUserNameInX {
		h.Write(I)
	}
	h.Write([]byte(":"))
	h.Write(P)
	digest := h.Sum(nil)
	h2 := params.Hash.New()

	h2.Write(salt)
	h2.Write(digest)
	x := new(big.Int)
	x.SetBytes(h2.Sum(nil))
	return x
}

// Digest digest_sha256
func (params *SRPParams) Digest(message []byte) []byte {
	h := params.Hash.New()
	h.Write(message)
	return h.Sum(nil)
}

// calculateM1 - icloud login version
func (params *SRPParams) calculateM1(username, salt, A, B, K []byte) []byte {
	digestn := params.Digest(padToN(params.G, params))
	digestg := params.Digest(params.N.Bytes())
	digesti := params.Digest(username)
	hxor := make([]byte, len(digestn))
	for i := range digestn {
		hxor[i] = digestn[i] ^ digestg[i]
	}
	h := params.Hash.New()
	h.Write(hxor)
	h.Write(digesti)
	h.Write(salt)
	h.Write(A)
	h.Write(B)
	h.Write(K)
	m1 := h.Sum(nil)
	return m1
}
func (params *SRPParams) calculateM2(A, M1, K []byte) []byte {
	h := params.Hash.New()
	h.Write(A)
	h.Write(M1)
	h.Write(K)
	return h.Sum(nil)
}

func (params *SRPParams) getMultiplier() *big.Int {
	h := params.Hash.New()
	n := params.N.Bytes()
	g := params.G.Bytes()
	for len(g) < len(n) {
		g = append([]byte{0}, g...)
	}
	h.Write(append(n, g...))
	return hashToInt(h)
}

// ComputeVerifier returns a verifier that is calculated as described in
// Section 3 of [SRP-RFC]
func ComputeVerifier(params *SRPParams, salt, identity, password []byte) []byte {
	x := params.calculateX(salt, identity, password)
	vNum := new(big.Int)
	vNum.Exp(params.G, x, params.N)
	return padToN(vNum, params)
}
