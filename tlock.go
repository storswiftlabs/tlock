// Package tlock provides an API for encrypting/decrypting data using
// drand time lock encryption. This allows data to be encrypted and only
// decrypted in the future.
package tlock

import (
	"bufio"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"strconv"
	"time"

	"filippo.io/age/armor"

	"filippo.io/age"
	"github.com/drand/drand/chain"
	"github.com/drand/drand/common/scheme"
	"github.com/drand/kyber"
	bls "github.com/drand/kyber-bls12381"
	"github.com/drand/kyber/encrypt/ibe"
)

// ErrTooEarly represents an error when a decryption operation happens early.
var ErrTooEarly = errors.New("too early to decrypt")

const (
	kyberPointLen = 48
	cipherVLen    = 16
	cipherWLen    = 16
)

// =============================================================================

// MetaData represents the metadata that must exist in the encrypted output
// to support CipherDEK decryption.
type MetaData struct {
	RoundNumber uint64
	ChainHash   string
}

// CipherDEK represents the encrypted data encryption key (DEK) needed to decrypt
// the cipher data.
type CipherDEK struct {
	KyberPoint []byte
	CipherV    []byte
	CipherW    []byte
}

// CipherInfo represents the data that is encoded and decoded.
type CipherInfo struct {
	MetaData   MetaData  // Metadata provides information to decrypt the CipherDEK.
	CipherDEK  CipherDEK // CipherDEK represents the key to decrypt the CipherData.
	CipherData []byte    // CipherData represents the data that has been encrypted.
}

// =============================================================================

// Network represents a system that provides support for encrypting/decrypting
// a DEK based on a future time.
type Network interface {
	Host() string
	ChainHash() string
	PublicKey() (kyber.Point, error)
	IsReadyToDecrypt(roundNumber uint64) (id []byte, ready bool)
	RoundNumber(t time.Time) (uint64, error)
}

// Decoder knows how to decode CipherInfo from the specified source.
type Decoder interface {
	Decode(in io.Reader, armor bool) (CipherInfo, error)
}

// Encoder knows how to encode CipherInfo to the specified destination.
type Encoder interface {
	Encode(out io.Writer, cipherInfo CipherInfo, armor bool) error
}

// DataEncrypter encrypts plain data with the specified key.
type DataEncrypter interface {
	Encrypt(key []byte, plainData []byte) (cipherData []byte, err error)
}

// DataDecrypter decrypts cipher data with the specified key.
type DataDecrypter interface {
	Decrypt(key []byte, cipherData []byte) (plainData []byte, err error)
}

// =============================================================================

// TLERecipient implements the age Recipient interface. This is used to encrypt
// data with the age Encrypt API.
type TLERecipient struct {
	round   uint64
	network Network
}

// Wrap is called by the age Encrypt API and is provided the DEK generated by
// age that is used for encrypting/decrypting data. Inside of Wrap we encrypt
// the DEK using time lock encryption.
func (t *TLERecipient) Wrap(fileKey []byte) ([]*age.Stanza, error) {
	id, err := calculateEncryptionID(t.round)
	if err != nil {
		return nil, fmt.Errorf("round by number: %w", err)
	}

	publicKey, err := t.network.PublicKey()
	if err != nil {
		return nil, fmt.Errorf("public key: %w", err)
	}

	cipherText, err := ibe.Encrypt(bls.NewBLS12381Suite(), publicKey, id, fileKey)
	if err != nil {
		return nil, fmt.Errorf("encrypt dek: %w", err)
	}

	kyberPoint, err := cipherText.U.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("marshal kyber point: %w", err)
	}

	cipherDEK := make([]byte, kyberPointLen+cipherVLen+cipherWLen)
	copy(cipherDEK, kyberPoint)
	copy(cipherDEK[kyberPointLen:], cipherText.V)
	copy(cipherDEK[kyberPointLen+cipherVLen:], cipherText.W)

	stanza := age.Stanza{
		Type: "tlock",
		Args: []string{strconv.FormatUint(t.round, 10), t.network.ChainHash()},
		Body: cipherDEK,
	}

	return []*age.Stanza{&stanza}, nil
}

// =============================================================================

// TLEIdentity implements the age Identity interface. This is used to decrypt
// data with the age Decrypt API.
type TLEIdentity struct {
	network Network
}

// Unwrap is called by the age Decrypt API and is provided the DEK that was time
// lock encrypted by the Wrap function via the Stanza. Inside of Unwrap we decrypt
// the DEK and provide back to age.
func (t *TLEIdentity) Unwrap(stanzas []*age.Stanza) ([]byte, error) {
	if len(stanzas) != 1 {
		return nil, errors.New("check stanzas length: should be one")
	}

	stanza := stanzas[0]

	if stanza.Type != "tlock" {
		return nil, fmt.Errorf("check stanza type: wrong type: %w", age.ErrIncorrectIdentity)
	}

	if len(stanza.Args) != 2 {
		return nil, fmt.Errorf("check stanza args: should be two: %w", age.ErrIncorrectIdentity)
	}

	blockRound, err := strconv.ParseUint(stanza.Args[0], 10, 64)
	if err != nil {
		return nil, fmt.Errorf("parse block round: %w", err)
	}

	if t.network.ChainHash() != stanza.Args[1] {
		return nil, errors.New("wrong chainhash")
	}

	cipherDEK, err := parseCipherDEK(stanza.Body)
	if err != nil {
		return nil, fmt.Errorf("parse cipher dek: %w", err)
	}

	plainDEK, err := decryptDEK(cipherDEK, t.network, blockRound)
	if err != nil {
		return nil, fmt.Errorf("decrypt dek: %w", err)
	}

	return plainDEK, nil
}

// parseCipherDEK parses the stanzaBody constructed in the Wrap method back to
// the original cipherDEK.
func parseCipherDEK(stanzaBody []byte) (CipherDEK, error) {
	expLen := kyberPointLen + cipherVLen + cipherWLen
	if len(stanzaBody) != expLen {
		return CipherDEK{}, fmt.Errorf("incorrect length: exp: %d got: %d", expLen, len(stanzaBody))
	}

	kyberPoint := make([]byte, kyberPointLen)
	copy(kyberPoint, stanzaBody[:kyberPointLen])

	cipherV := make([]byte, cipherVLen)
	copy(cipherV, stanzaBody[kyberPointLen:kyberPointLen+cipherVLen])

	cipherW := make([]byte, cipherVLen)
	copy(cipherW, stanzaBody[kyberPointLen+cipherVLen:])

	cd := CipherDEK{
		KyberPoint: kyberPoint,
		CipherV:    cipherV,
		CipherW:    cipherW,
	}

	return cd, nil
}

// decryptDEK attempts to decrypt an encrypted DEK against the provided network
// for the specified round.
func decryptDEK(cipherDEK CipherDEK, network Network, roundNumber uint64) (plainDEK []byte, err error) {
	id, ready := network.IsReadyToDecrypt(roundNumber)
	if !ready {
		return nil, ErrTooEarly
	}

	var dekSignature bls.KyberG2
	if err := dekSignature.UnmarshalBinary(id); err != nil {
		return nil, fmt.Errorf("unmarshal kyber G2: %w", err)
	}

	var dekKyberPoint bls.KyberG1
	if err := dekKyberPoint.UnmarshalBinary(cipherDEK.KyberPoint); err != nil {
		return nil, fmt.Errorf("unmarshal kyber G1: %w", err)
	}

	publicKey, err := network.PublicKey()
	if err != nil {
		return nil, fmt.Errorf("public key: %w", err)
	}

	b := chain.Beacon{
		Round:     roundNumber,
		Signature: id,
	}
	sch := scheme.Scheme{
		ID:              scheme.UnchainedSchemeID,
		DecouplePrevSig: true,
	}
	if err := chain.NewVerifier(sch).VerifyBeacon(b, publicKey); err != nil {
		return nil, fmt.Errorf("verify beacon: %w", err)
	}

	dek := ibe.Ciphertext{
		U: &dekKyberPoint,
		V: cipherDEK.CipherV,
		W: cipherDEK.CipherW,
	}

	plainDEK, err = ibe.Decrypt(bls.NewBLS12381Suite(), publicKey, &dekSignature, &dek)
	if err != nil {
		return nil, fmt.Errorf("decrypt dek: %w", err)
	}

	return plainDEK, nil
}

// =============================================================================

// Encrypter provides an API for time lock encryption.
type Encrypter struct {
	network Network
}

// NewEncrypter constructs a Tlock for use with the specified network, encrypter, and encoder.
func NewEncrypter(network Network) Encrypter {
	return Encrypter{
		network: network,
	}
}

// Encrypt will encrypt the data that is read by the reader which can only be
// decrypted in the future specified round.
func (t Encrypter) Encrypt(out io.Writer, in io.Reader, roundNumber uint64) error {
	w, err := age.Encrypt(out, &TLERecipient{network: t.network, round: roundNumber})
	if err != nil {
		return fmt.Errorf("age encrypt: %w", err)
	}

	if _, err := io.Copy(w, in); err != nil {
		return fmt.Errorf("read: %w", err)
	}

	if err := w.Close(); err != nil {
		return fmt.Errorf("close: %w", err)
	}

	return nil
}

// calculateEncryptionID will generate the id required for encryption.
func calculateEncryptionID(roundNumber uint64) ([]byte, error) {
	h := sha256.New()
	if _, err := h.Write(chain.RoundToBytes(roundNumber)); err != nil {
		return nil, fmt.Errorf("sha256 write: %w", err)
	}

	return h.Sum(nil), nil
}

// =============================================================================

// Decrypter provides an API for time lock decryption.
type Decrypter struct {
	network Network
}

// NewDecrypter constructs a Tlock for use with the specified network, decrypter, and decoder.
func NewDecrypter(network Network) Decrypter {
	return Decrypter{
		network: network,
	}
}

// Decrypt decode the input source for a CipherData value. For each CipherData
// value that is decoded, the DEK is decrypted with time lock decryption so
// the cipher data can then be decrypted with that key and written to the
// specified output destination.
func (t Decrypter) Decrypt(out io.Writer, in io.Reader) error {
	rr := bufio.NewReader(in)

	if start, _ := rr.Peek(len(armor.Header)); string(start) == armor.Header {
		in = armor.NewReader(rr)
	} else {
		in = rr
	}

	plainReader, err := age.Decrypt(in, &TLEIdentity{network: t.network})
	if err != nil {
		return fmt.Errorf("age decrypt: %w", err)
	}

	if _, err := io.Copy(out, plainReader); err != nil {
		return fmt.Errorf("write out: %w", err)
	}

	return nil
}
