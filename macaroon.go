package l402

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"reflect"
	"strings"

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

func UnmarshalMacaroons(macaroonsBase64 string) (map[Identifier]macaroon.Macaroon, error) {
	splitMacaroonBase64 := strings.Split(macaroonsBase64, ",")
	macaroonCount := len(splitMacaroonBase64)

	switch macaroonCount {
	case 1:
		macaroons := make(map[Identifier]macaroon.Macaroon, 1)
		macaroon, identifier, err := UnmarshalMacaroon(splitMacaroonBase64[0])
		macaroons[identifier] = macaroon
		return macaroons, err
	default:
		macaroons := make(map[Identifier]macaroon.Macaroon, macaroonCount)
		for i, macaroonBase64 := range splitMacaroonBase64 {
			macaroon, identifier, err := UnmarshalMacaroon(macaroonBase64)
			if err != nil {
				return nil, fmt.Errorf("%w: index: %d", err, i)
			}
			macaroons[identifier] = macaroon
		}
		return macaroons, nil
	}
}

func MarshalMacaroon(macaroon macaroon.Macaroon) (string, error) {
	if encodedMacaroon, err := macaroon.MarshalBinary(); err != nil {
		return "", err
	} else {
		return base64.StdEncoding.EncodeToString(encodedMacaroon), nil
	}
}

func MarshalMacaroons(macaroons []macaroon.Macaroon) (string, error) {
	switch len(macaroons) {
	case 0:
		return "", errors.New("can't marshal empty macaroon slice")
	case 1:
		return MarshalMacaroon(macaroons[0])
	default:
		var macaroonsBase64 string
		for i, macaroon := range macaroons {
			if macaroonBase64, err := MarshalMacaroon(macaroon); err != nil {
				return "", fmt.Errorf("%w: index: %d", err, i)
			} else {
				macaroonsBase64 += "," + macaroonBase64
			}
		}
		return macaroonsBase64[1:], nil
	}
}

var byteOrder = binary.BigEndian

var (
	macaroonIdSize    = int(reflect.TypeFor[Identifier]().Size())
	versionOffet      = int(reflect.TypeFor[uint16]().Size())
	paymentHashOffset = int(reflect.TypeFor[Hash]().Size())
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
	if len(identifierBytes) != macaroonIdSize {
		return Identifier{}, ErrUnknownVersion
	}
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
