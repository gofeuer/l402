package l402

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"reflect"
	"strings"

	macaroon "gopkg.in/macaroon.v2"
)

const HashSize = sha256.Size

type (
	Hash [HashSize]byte
	ID   [HashSize]byte
)

type Identifier struct {
	Version     uint16
	PaymentHash Hash
	ID          ID
}

func MarshalMacaroons(macaroons ...*macaroon.Macaroon) (string, error) {
	macaroonBytes, err := macaroon.Slice(macaroons).MarshalBinary()
	macaroonBase64 := base64.StdEncoding.EncodeToString(macaroonBytes)
	return macaroonBase64, err
}

func UnmarshalMacaroons(macaroonBase64 string) (macaroon.Slice, error) {
	macaroonBytes, err := base64.StdEncoding.DecodeString(macaroonBase64)
	if err != nil {
		// The macaroons might be separated by commas, so we strip them and try again.
		macaroonBase64 = strings.ReplaceAll(macaroonBase64, ",", "")
		if macaroonBytes, err = base64.StdEncoding.DecodeString(macaroonBase64); err != nil {
			return nil, err
		}
	}

	macaroons := make(macaroon.Slice, 0, 1)
	return macaroons, macaroons.UnmarshalBinary(macaroonBytes)
}

var (
	identifierBytesLength = int(reflect.TypeFor[Identifier]().Size())
	versionOffset         = reflect.TypeFor[uint16]().Size()
	paymentHashOffset     = reflect.TypeFor[Hash]().Size()
)

func MarshalIdentifier(identifier Identifier) ([]byte, error) {
	if identifier.Version != 0 {
		return nil, ErrUnknownVersion(identifier.Version)
	}

	identifierBytes := make([]byte, identifierBytesLength)

	offset := versionOffset // Skip the version location, it's already initialized as zero.
	copy(identifierBytes[offset:], identifier.PaymentHash[:])

	offset += paymentHashOffset
	copy(identifierBytes[offset:], identifier.ID[:])

	return identifierBytes, nil
}

func UnmarshalIdentifier(identifierBytes []byte) (Identifier, error) {
	if len(identifierBytes) != identifierBytesLength {
		return Identifier{}, ErrUnknownVersion(-1)
	} else if version := binary.BigEndian.Uint16(identifierBytes); version != 0 {
		return Identifier{}, ErrUnknownVersion(version)
	}

	var identifier Identifier

	offset := versionOffset // Skip the version, we already know it's zero.
	copy(identifier.PaymentHash[:], identifierBytes[offset:])

	offset += paymentHashOffset
	copy(identifier.ID[:], identifierBytes[offset:])

	return identifier, nil
}

type ErrUnknownVersion int

func (e ErrUnknownVersion) Error() string {
	return fmt.Sprintf("unknown L402 version: %d", e)
}
