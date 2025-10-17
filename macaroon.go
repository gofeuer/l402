package l402

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"reflect"
	"strings"

	macaroon "gopkg.in/macaroon.v2"
)

type (
	Hash [sha256.Size]byte
	ID   [sha256.Size]byte
)

type Identifier struct {
	// Version uint16 = [0,0,...]
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
		// This error might be caused by the macaroons being separated by commas,
		// so we strip away the commas and try again.
		macaroonBase64 = strings.ReplaceAll(macaroonBase64, ",", "")
		if macaroonBytes, err = base64.StdEncoding.DecodeString(macaroonBase64); err != nil {
			return nil, err
		}
	}

	macaroons := make(macaroon.Slice, 0, 1)
	return macaroons, macaroons.UnmarshalBinary(macaroonBytes)
}

var (
	paymentHashOffset     = reflect.TypeFor[uint16]().Size() // Space for the version number.
	idOffset              = reflect.TypeFor[uint16]().Size() + reflect.TypeFor[Hash]().Size()
	identifierBytesLength = reflect.TypeFor[uint16]().Size() + reflect.TypeFor[Identifier]().Size()
)

func MarshalIdentifier(identifier Identifier) []byte {
	identifierBytes := make([]byte, identifierBytesLength)
	copy(identifierBytes[paymentHashOffset:], identifier.PaymentHash[:])
	copy(identifierBytes[idOffset:], identifier.ID[:])
	return identifierBytes
}

func UnmarshalIdentifier(identifierBytes []byte) (Identifier, error) {
	if len(identifierBytes) != int(identifierBytesLength) {
		return Identifier{}, ErrUnknownVersion(-1)
	} else if version := binary.BigEndian.Uint16(identifierBytes); version != 0 {
		return Identifier{}, ErrUnknownVersion(version)
	}

	var identifier Identifier
	copy(identifier.PaymentHash[:], identifierBytes[paymentHashOffset:])
	copy(identifier.ID[:], identifierBytes[idOffset:])
	return identifier, nil
}
