package tlock_test

import (
	"bytes"
	_ "embed" // Calls init function.
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/drand/drand/chain"
	"github.com/drand/drand/crypto"
	bls "github.com/drand/kyber-bls12381"
	"github.com/drand/tlock"
	"github.com/drand/tlock/networks/http"
	"github.com/stretchr/testify/require"
)

var (
	//go:embed test_artifacts/data.txt
	dataFile []byte
)

const (
	testnetHost      = "https://pl-us.testnet.drand.sh/"
	testnetChainHash = "cc9c398442737cbd141526600919edd69f1d6f9b4adb67e4d912fbc64341a9a5"
	mainnetHost      = "https://api.drand.sh/"
	mainnetChainHash = "52db9ba70e0cc0f6eaf7803dd07447a1f5477735fd3f661792ba94600c84e971"
)

func TestEarlyDecryptionWithDuration(t *testing.T) {
	for host, hash := range map[string]string{testnetHost: testnetChainHash, mainnetHost: mainnetChainHash} {
		network, err := http.NewNetwork(host, hash)
		require.NoError(t, err)

		// =========================================================================
		// Encrypt

		// Read the plaintext data to be encrypted.
		in, err := os.Open("test_artifacts/data.txt")
		require.NoError(t, err)
		defer in.Close()

		// Write the encoded information to this buffer.
		var cipherData bytes.Buffer

		// Enough duration to check for a non-existent beacon.
		duration := 10 * time.Second

		roundNumber := network.RoundNumber(time.Now().Add(duration))
		err = tlock.New(network).Encrypt(&cipherData, in, roundNumber)
		require.NoError(t, err)

		// =========================================================================
		// Decrypt

		// Write the decoded information to this buffer.
		var plainData bytes.Buffer

		// We DO NOT wait for the future beacon to exist.
		err = tlock.New(network).Decrypt(&plainData, &cipherData)
		require.ErrorIs(t, err, tlock.ErrTooEarly)
	}
}

func TestEarlyDecryptionWithRound(t *testing.T) {
	network, err := http.NewNetwork(testnetHost, testnetChainHash)
	require.NoError(t, err)

	// =========================================================================
	// Encrypt

	// Read the plaintext data to be encrypted.
	in, err := os.Open("test_artifacts/data.txt")
	require.NoError(t, err)
	defer in.Close()

	var cipherData bytes.Buffer
	futureRound := network.RoundNumber(time.Now().Add(1 * time.Minute))

	err = tlock.New(network).Encrypt(&cipherData, in, futureRound)
	require.NoError(t, err)

	// =========================================================================
	// Decrypt

	// Write the decoded information to this buffer.
	var plainData bytes.Buffer

	// We DO NOT wait for the future beacon to exist.
	err = tlock.New(network).Decrypt(&plainData, &cipherData)
	require.ErrorIs(t, err, tlock.ErrTooEarly)
}

func TestEncryptionWithDuration(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping live testing in short mode")
	}

	network, err := http.NewNetwork(testnetHost, testnetChainHash)
	require.NoError(t, err)

	// =========================================================================
	// Encrypt

	// Read the plaintext data to be encrypted.
	in, err := os.Open("test_artifacts/data.txt")
	require.NoError(t, err)
	defer in.Close()

	// Write the encoded information to this buffer.
	var cipherData bytes.Buffer

	// Enough duration to check for a non-existent beacon.
	duration := 4 * time.Second

	roundNumber := network.RoundNumber(time.Now().Add(duration))
	err = tlock.New(network).Encrypt(&cipherData, in, roundNumber)
	require.NoError(t, err)

	// =========================================================================
	// Decrypt

	time.Sleep(5 * time.Second)

	// Write the decoded information to this buffer.
	var plainData bytes.Buffer

	err = tlock.New(network).Decrypt(&plainData, &cipherData)
	require.NoError(t, err)

	if !bytes.Equal(plainData.Bytes(), dataFile) {
		t.Fatalf("decrypted file is invalid; expected %d; got %d", len(dataFile), len(plainData.Bytes()))
	}
}

func TestEncryptionWithRound(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping live testing in short mode")
	}

	network, err := http.NewNetwork(testnetHost, testnetChainHash)
	require.NoError(t, err)

	// =========================================================================
	// Encrypt

	// Read the plaintext data to be encrypted.
	in, err := os.Open("test_artifacts/data.txt")
	require.NoError(t, err)
	defer in.Close()

	// Write the encoded information to this buffer.
	var cipherData bytes.Buffer

	futureRound := network.RoundNumber(time.Now().Add(6 * time.Second))
	err = tlock.New(network).Encrypt(&cipherData, in, futureRound)
	require.NoError(t, err)

	// =========================================================================
	// Decrypt

	var plainData bytes.Buffer

	// Wait for the future beacon to exist.
	time.Sleep(10 * time.Second)

	err = tlock.New(network).Decrypt(&plainData, &cipherData)
	require.NoError(t, err)

	if !bytes.Equal(plainData.Bytes(), dataFile) {
		t.Fatalf("decrypted file is invalid; expected %d; got %d", len(dataFile), len(plainData.Bytes()))
	}
}

func TestTimeLockUnlock(t *testing.T) {
	network, err := http.NewNetwork(testnetHost, testnetChainHash)
	require.NoError(t, err)

	futureRound := network.RoundNumber(time.Now())

	id, err := network.Signature(futureRound)
	require.NoError(t, err)

	data := []byte(`anything`)

	cipherText, err := tlock.TimeLock(network.Scheme(), network.PublicKey(), futureRound, data)
	require.NoError(t, err)

	beacon := chain.Beacon{
		Round:     futureRound,
		Signature: id,
	}

	b, err := tlock.TimeUnlock(network.Scheme(), network.PublicKey(), beacon, cipherText)
	require.NoError(t, err)

	if !bytes.Equal(data, b) {
		t.Fatalf("unexpected bytes; expected len %d; got %d", len(data), len(b))
	}
}

func TestCannotEncryptWithPointAtInfinity(t *testing.T) {
	suite := bls.NewBLS12381Suite()
	t.Run("on G2", func(t *testing.T) {
		infinity := suite.G2().Scalar().Zero()
		pointAtInfinity := suite.G2().Point().Mul(infinity, nil)

		_, err := tlock.TimeLock(*crypto.NewPedersenBLSUnchainedSwapped(), pointAtInfinity, 10, []byte("deadbeef"))
		require.ErrorIs(t, err, tlock.ErrInvalidPublicKey)
	})

	t.Run("on G1", func(t *testing.T) {
		infinity := suite.G1().Scalar().Zero()
		pointAtInfinity := suite.G1().Point().Mul(infinity, nil)

		_, err := tlock.TimeLock(*crypto.NewPedersenBLSUnchained(), pointAtInfinity, 10, []byte("deadbeef"))
		require.ErrorIs(t, err, tlock.ErrInvalidPublicKey)
	})

}

func TestDecryptText(t *testing.T) {
	cipher := `-----BEGIN AGE ENCRYPTED FILE-----
YWdlLWVuY3J5cHRpb24ub3JnL3YxCi0+IHRsb2NrIDM5MTUwNiA1MmRiOWJhNzBl
MGNjMGY2ZWFmNzgwM2RkMDc0NDdhMWY1NDc3NzM1ZmQzZjY2MTc5MmJhOTQ2MDBj
ODRlOTcxCmxkby91Wkx4eW1rc3Z4WDNIVWxDREpEdm5sWE1qeFU1K09JditIMFlK
ak5sUFQwbWwvNUtyemUxQnhTT2RNTkkKRXF3ZDBVV1RBWU1PVHBlV0R3L2d0c2hN
OUhkWUE0YzJJdGMxcUFoRElUR2NKQkh0Nnc5N2dIUldadVZ4UU5yaApONWNPNyty
QkJRSkY4MlFRRkJZVUMxNGpiL1VZYjNGaDFsUVNuelVic0dVCi0tLSAxb1NNRnp6
M2NqcDBjT3FVdmtIQnQ5Y044MUlsV3hZM29GZVg5T05hSzdFCjkZYt1Cam0OPjdn
WdBQADOMF88wDRmZEnDw+D1j/8NrJXLI87enseShAns+L/NkNGhA8oiA+ZxaTbfs
wcryvxRQprkmX2IEfSUWZWyCTV47cA+5XEdfpFK0Ull7VaTh7dhkcozwc5kruI8Z
1txsd/vjXpKRj199cfL6tEIH0fR+re6AHhCRljKWhsUpCyGuRnBFO5/KpVsTPx3h
hbioFa3010UG
-----END AGE ENCRYPTED FILE-----`
	t.Run("With valid network", func(tt *testing.T) {
		network, err := http.NewNetwork(mainnetHost, mainnetChainHash)
		require.NoError(tt, err)

		testReader := strings.NewReader(cipher)
		var plainData bytes.Buffer

		err = tlock.New(network).Decrypt(&plainData, testReader)
		require.NoError(tt, err)

		type Message struct {
			Time    int    `json:"Time"`
			Option  string `json:"option"`
			Address string `json:"Address"`
		}
		expected := Message{1693810319389, "Yes\n", "0x8f794a441b5cc022926027d29fa1ce173793976577d614abc25921b225f99db7"}

		var fromJson Message
		err = json.Unmarshal(plainData.Bytes(), &fromJson)
		require.NoError(tt, err)

		require.Equal(tt, expected, fromJson)
	})

	t.Run("With invalid network", func(tt *testing.T) {
		network, err := http.NewNetwork(testnetHost, testnetChainHash)
		require.NoError(tt, err)

		testReader := strings.NewReader(cipher)
		var plainData bytes.Buffer

		err = tlock.New(network).Decrypt(&plainData, testReader)
		require.ErrorIs(tt, err, tlock.ErrWrongChainhash)
	})
}

func TestInteropWithJS(t *testing.T) {
	t.Run("on Mainnet with G1 sigs", func(t *testing.T) {
		cipher := `-----BEGIN AGE ENCRYPTED FILE-----
YWdlLWVuY3J5cHRpb24ub3JnL3YxCi0+IHRsb2NrIDMzOTU5MiA1MmRiOWJhNzBl
MGNjMGY2ZWFmNzgwM2RkMDc0NDdhMWY1NDc3NzM1ZmQzZjY2MTc5MmJhOTQ2MDBj
ODRlOTcxCmpUd2pKVnN4ZHpBOVJkZk4vRDhFM0Ira3AvNTVDTHVGMlFnaTE4b1Z1
aHdFL1d6SUxZQk5VNkZPRUM5MVRIZW8KRk5pSnN4RUppU3pqbnRGRHZCWlpxaHRx
UHRyL3dyZXRnYmhsN0JSZm9KM1hPMy9qUzZFL0prVldqeEhWZWMzVQoxenZIY2o3
TFJjYlFQaVFuT2NoUnZxbWxTS0I2YWFVenlzdjNjdTJwQUhvCi0tLSBNbnJqbTJ1
cFFvS3l2azkrSmlaM1BjNWtLYUhpMktSOEk1VkdsUmJQMmZzCtj+TQ33fW5scRgm
iQdyc3S+14kzFECervdIV0YEQNMYJczz6dAHu1C3vCvbFRs=
-----END AGE ENCRYPTED FILE-----`
		expected := "hello quicknet"
		network, err := http.NewNetwork(mainnetHost, mainnetChainHash)
		require.NoError(t, err)

		testReader := strings.NewReader(cipher)
		var plainData bytes.Buffer

		err = tlock.New(network).Decrypt(&plainData, testReader)
		require.NoError(t, err)

		require.Equal(t, expected, plainData.String())
	})

	t.Run("on Testnet with G1 sigs", func(t *testing.T) {
		cipher := `-----BEGIN AGE ENCRYPTED FILE-----
YWdlLWVuY3J5cHRpb24ub3JnL3YxCi0+IHRsb2NrIDE1MzAwNDUgY2M5YzM5ODQ0
MjczN2NiZDE0MTUyNjYwMDkxOWVkZDY5ZjFkNmY5YjRhZGI2N2U0ZDkxMmZiYzY0
MzQxYTlhNQp1QjNLbmlaeVFDbGk1d0N4b25OL2UvQzFYMmI1ZzMyWW01VWRwVEtR
aGtQM3l4TUMxdWhlaFdDZ0NRS0hKcDU5CkV0UkNXazhCckNlWVArcnduZjR2OVd3
dWpFWk11TGp1SUt1Q3F1SXdNcEdUaHc0VXJEbEVablU5ZndPZDBkcXgKejd6aXZR
bFFVQU44ekhZWjhwM2RJekR4NC9la25OQWk5UHhUN1daYTFCTQotLS0gNXZDS3lY
ZlVySU92d29LZEhGR2h6ZUZiVitQSjBsNEVnM1JtWC9INm9YWQoyPsJWIBkmJPZi
oG32+guUclyoVQKHLIGYYAQ5QjSP0TRi6NqURkKBMpPyUe/D
-----END AGE ENCRYPTED FILE-----`
		expected := "hello quicknet"
		network, err := http.NewNetwork(testnetHost, testnetChainHash)
		require.NoError(t, err)

		testReader := strings.NewReader(cipher)
		var plainData bytes.Buffer

		err = tlock.New(network).Decrypt(&plainData, testReader)
		require.NoError(t, err)

		require.Equal(t, expected, plainData.String())
	})
}
