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
	ID          ID
}

func UnmarshalMacaroon(macaroonBase64 string) (Identifier, macaroon.Macaroon, error) {
	macaroonBytes, err := base64.StdEncoding.DecodeString(macaroonBase64)
	if err != nil {
		return Identifier{}, macaroon.Macaroon{}, err
	}

	macaroon := macaroon.Macaroon{}
	if err := macaroon.UnmarshalBinary(macaroonBytes); err != nil {
		return Identifier{}, macaroon, err
	}

	identifier, err := UnmarshalIdentifier(macaroon.Id())
	return identifier, macaroon, err
}

func UnmarshalMacaroons(macaroonsBase64 string) (map[Identifier]macaroon.Macaroon, error) {
	// Optimistically expect only one macaroon
	if identifier, mac, err := UnmarshalMacaroon(macaroonsBase64); err == nil {
		macaroons := make(map[Identifier]macaroon.Macaroon, 1)
		macaroons[identifier] = mac
		return macaroons, nil
	} else if _, isInputError := err.(base64.CorruptInputError); !isInputError {
		return nil, err
	}

	// A base64.CorruptInputError means that macaroonsBase64 likely contains commas
	// So we try unmarshal macaroonsBase64 again expecting it to have multiple macaroons
	macaroons := make(map[Identifier]macaroon.Macaroon)
	for i, macaroonBase64 := range strings.Split(macaroonsBase64, ",") {
		identifier, macaroon, err := UnmarshalMacaroon(macaroonBase64)
		if err != nil {
			return nil, fmt.Errorf("index %d: %w", i, err)
		}
		macaroons[identifier] = macaroon
	}
	return macaroons, nil
}

func MarshalMacaroon(macaroon macaroon.Macaroon) (string, error) {
	encodedMacaroon, err := macaroon.MarshalBinary()
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(encodedMacaroon), nil
}

func MarshalMacaroons(macaroons []macaroon.Macaroon) (string, error) {
	switch len(macaroons) {
	case 0:
		return "", errors.New("can't marshal empty macaroon slice") //nolint:err113
	case 1:
		return MarshalMacaroon(macaroons[0])
	default:
		var macaroonsBase64 string
		for i, macaroon := range macaroons {
			macaroonBase64, err := MarshalMacaroon(macaroon)
			if err != nil {
				return "", fmt.Errorf("index %d: %w", i, err)
			}
			macaroonsBase64 += "," + macaroonBase64
		}
		return macaroonsBase64[1:], nil
	}
}

var byteOrder = binary.BigEndian

var (
	macaroonIDSize    = int(reflect.TypeFor[Identifier]().Size())
	versionOffet      = int(reflect.TypeFor[uint16]().Size())
	paymentHashOffset = int(reflect.TypeFor[Hash]().Size())
)

func MarchalIdentifier(identifier Identifier) ([]byte, error) {
	if identifier.Version != 0 {
		return nil, fmt.Errorf("%w: %v", ErrUnknownVersion, identifier.Version)
	}

	macaroonID := make([]byte, macaroonIDSize)

	offset := versionOffet // Skip the version location, it's already initialized as zero
	copy(macaroonID[offset:], identifier.PaymentHash[:])

	offset += paymentHashOffset
	copy(macaroonID[offset:], identifier.ID[:])

	return macaroonID, nil
}

func UnmarshalIdentifier(identifierBytes []byte) (Identifier, error) {
	if len(identifierBytes) != macaroonIDSize {
		return Identifier{}, ErrUnknownVersion
	}
	if version := byteOrder.Uint16(identifierBytes); version != 0 {
		return Identifier{}, fmt.Errorf("%w: %v", ErrUnknownVersion, version)
	}

	var identifier Identifier

	offset := versionOffet // Skip the version, we alredy know it's zero
	copy(identifier.PaymentHash[:], identifierBytes[offset:])

	offset += paymentHashOffset
	copy(identifier.ID[:], identifierBytes[offset:])

	return identifier, nil
}
