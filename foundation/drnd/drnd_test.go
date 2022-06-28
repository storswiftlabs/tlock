package drnd_test

import (
	"bytes"
	"context"
	_ "embed" // Calls init function.
	"os"
	"strings"
	"testing"
	"time"

	"github.com/drand/tlock/foundation/drnd"
	"github.com/drand/tlock/foundation/encrypters/aead"
	"github.com/drand/tlock/foundation/networks/http"
)

var (
	//go:embed test_artifacts/decryptedFile.bin
	decryptedFile []byte

	//go:embed test_artifacts/encryptedFile.bin
	encryptedFile []byte

	//go:embed test_artifacts/data.txt
	dataFile []byte
)

const (
	testnetHost      = "http://pl-us.testnet.drand.sh/"
	testnetChainHash = "7672797f548f3f4748ac4bf3352fc6c6b6468c9ad40ad456a397545c6e2df5bf"
)

func Test_EarlyDecryption(t *testing.T) {
	network := http.New(testnetHost, testnetChainHash)

	// read the data to be encrypted.
	reader, err := os.Open("test_artifacts/data.txt")
	if err != nil {
		t.Fatalf("reader error %s", err)
	}
	defer reader.Close()

	var aead aead.AEAD

	// Enough duration to check for an non-existing beacon.
	duration := 10 * time.Second

	var encryptedBuffer bytes.Buffer
	err = drnd.EncryptWithDuration(context.Background(), &encryptedBuffer, reader, network, aead, duration, false)
	if err != nil {
		t.Fatalf("encrypt with duration error %s", err)
	}

	var decryptedBuffer bytes.Buffer

	// We DO NOT wait for the future beacon to exist.
	err = drnd.Decrypt(context.Background(), &decryptedBuffer, &encryptedBuffer, network, aead)
	if err == nil {
		t.Fatal("expecting decrypt error")
	}

	if !strings.Contains(err.Error(), drnd.ErrTooEarly) {
		t.Fatalf("expecting decrypt error to contain '%s'; got %s", drnd.ErrTooEarly, err)
	}
}

func Test_EncryptionWithDuration(t *testing.T) {
	network := http.New(testnetHost, testnetChainHash)

	// read the data to be encrypted.
	reader, err := os.Open("test_artifacts/data.txt")
	if err != nil {
		t.Fatalf("reader error %s", err)
	}
	defer reader.Close()

	var aead aead.AEAD

	// This is the testnetwork period.
	duration := 3 * time.Second

	var encryptedBuffer bytes.Buffer
	err = drnd.EncryptWithDuration(context.Background(), &encryptedBuffer, reader, network, aead, duration, false)
	if err != nil {
		t.Fatalf("encrypt with duration error %s", err)
	}

	//==========================================================================
	// The encrypted buffer was written. We need to decrypt to make sure it worked.
	var decryptedBuffer bytes.Buffer

	// Wait for the future beacon to exist.
	time.Sleep(4 * time.Second)

	err = drnd.Decrypt(context.Background(), &decryptedBuffer, &encryptedBuffer, network, aead)
	if err != nil {
		t.Fatalf("decrypt error %s", err)
	}

	if !bytes.Equal(decryptedBuffer.Bytes(), dataFile) {
		t.Fatalf("decrypted file is invalid; expected %d; got %d", len(dataFile), len(decryptedBuffer.Bytes()))
	}
}

func Test_Decryption(t *testing.T) {
	network := http.New(testnetHost, testnetChainHash)

	// read encrypted data.
	reader, err := os.Open("test_artifacts/encryptedFile.bin")
	if err != nil {
		t.Fatalf("reader error %s", err)
	}
	defer reader.Close()

	var aead aead.AEAD

	var encryptedBuffer bytes.Buffer
	err = drnd.Decrypt(context.Background(), &encryptedBuffer, reader, network, aead)
	if err != nil {
		t.Fatalf("decrypt error %s", err)
	}

	size := encryptedBuffer.Bytes()
	if !bytes.Equal(size, decryptedFile) {
		t.Fatalf("decrypted buffer is invalid; expected %d; got %d", len(decryptedFile), len(size))
	}
}
