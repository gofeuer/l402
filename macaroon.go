package l402

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"reflect"

	macaroon "gopkg.in/macaroon.v2"
)

const BlockSize = sha256.Size

type (
	ByteBlock [BlockSize]byte
	Hash      ByteBlock
	ID        ByteBlock
)

type Identifier struct {
	Version     uint16
	PaymentHash Hash
	Id          ID
}

func UnmarshalMacaroon(macaroonBase64 string) (macaroon.Macaroon, Identifier, error) {
	macaroonBytes, err := base64.StdEncoding.DecodeString(macaroonBase64)
	if err != nil {
		return macaroon.Macaroon{}, Identifier{}, err
	}

	macaroon := macaroon.Macaroon{}
	if err := macaroon.UnmarshalBinary(macaroonBytes); err != nil {
		return macaroon, Identifier{}, err
	}

	identifier, err := UnmarshalIdentifier(macaroon.Id())

	return macaroon, identifier, err
}

func MarshalMacaroon(macaroon macaroon.Macaroon) (string, error) {
	if encodedMacaroon, err := macaroon.MarshalBinary(); err != nil {
		return "", err
	} else {
		return base64.StdEncoding.EncodeToString(encodedMacaroon), nil
	}
}

var byteOrder = binary.BigEndian

var (
	macaroonIdSize    = reflect.TypeFor[Identifier]().Size()
	versionOffet      = reflect.TypeFor[uint16]().Size()
	paymentHashOffset = reflect.TypeFor[Hash]().Size()
)

func MarchalIdentifier(identifier Identifier) ([]byte, error) {
	if identifier.Version != 0 {
		return nil, fmt.Errorf("%w: %v", ErrUnknownVersion, identifier.Version)
	}

	macaroonID := make([]byte, macaroonIdSize)

	offset := versionOffet // Skip the version location, it's already initialized as zero
	copy(macaroonID[offset:], identifier.PaymentHash[:])

	offset += paymentHashOffset
	copy(macaroonID[offset:], identifier.Id[:])

	return macaroonID, nil
}

func UnmarshalIdentifier(identifierBytes []byte) (Identifier, error) {
	if version := byteOrder.Uint16(identifierBytes); version != 0 {
		return Identifier{}, fmt.Errorf("%w: %v", ErrUnknownVersion, version)
	}

	var identifier Identifier

	offset := versionOffet // Skip the version, we alredy know it's zero
	copy(identifier.PaymentHash[:], identifierBytes[offset:])

	offset += paymentHashOffset
	copy(identifier.Id[:], identifierBytes[offset:])

	return identifier, nil
}
