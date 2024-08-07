package l402

import (
	"crypto/sha256"
	"encoding/binary"
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

func UnmarshalMacaroons(macaroonBase64 string) (map[Identifier]*macaroon.Macaroon, error) {
	if macaroonBase64 == "" {
		return nil, ErrEmptyMacaroonData
	}

	macaroonBytes, err := macaroon.Base64Decode([]byte(macaroonBase64))
	if err != nil {
		// The macaroons might be separated by commas, so we strip them and try again
		macaroonBase64 = strings.ReplaceAll(macaroonBase64, ",", "")
		if macaroonBytes, err = macaroon.Base64Decode([]byte(macaroonBase64)); err != nil {
			return nil, err
		}
	}

	macaroons := make(macaroon.Slice, 0, 1)
	if err := macaroons.UnmarshalBinary(macaroonBytes); err != nil {
		return nil, err
	}

	macaroonsMap := make(map[Identifier]*macaroon.Macaroon, len(macaroons))

	for i, macaroon := range macaroons {
		identifier, err := UnmarshalIdentifier(macaroon.Id())
		if err != nil {
			return nil, fmt.Errorf("index %d: %w", i, err)
		}
		macaroonsMap[identifier] = macaroon
	}
	return macaroonsMap, err
}

var byteOrder = binary.BigEndian

var (
	macaroonIDSize    = int(reflect.TypeFor[Identifier]().Size())
	versionOffet      = reflect.TypeFor[uint16]().Size()
	paymentHashOffset = reflect.TypeFor[Hash]().Size()
)

func MarchalIdentifier(identifier Identifier) ([]byte, error) {
	if identifier.Version != 0 {
		return nil, fmt.Errorf("%w: %d", ErrUnknownVersion, identifier.Version)
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
	} else if version := byteOrder.Uint16(identifierBytes); version != 0 {
		return Identifier{}, fmt.Errorf("%w: %d", ErrUnknownVersion, version)
	}

	var identifier Identifier

	offset := versionOffet // Skip the version, we alredy know it's zero
	copy(identifier.PaymentHash[:], identifierBytes[offset:])

	offset += paymentHashOffset
	copy(identifier.ID[:], identifierBytes[offset:])

	return identifier, nil
}
