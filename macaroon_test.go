package l402

import (
	"bytes"
	"encoding/base64"
	"errors"
	"reflect"
	"testing"

	macaroon "gopkg.in/macaroon.v2"
)

func TestMarshalMacaroons(t *testing.T) {
	mac1, _ := macaroon.New([]byte{1}, []byte{
		0, 0, // Version
		1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // Payment Hash
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2,
		3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // Id
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4}, "", macaroon.V2)
	mac2, _ := macaroon.New([]byte{1}, []byte{
		0, 0, // Version
		1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // Payment Hash
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2,
		3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // Id
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 5}, "", macaroon.V2)

	tests := map[string]struct {
		macaroons              macaroon.Slice
		expectedMacaroonBase64 string
		expectedError          error
	}{
		"zero": {
			expectedError: nil,
		},
		"one": {
			macaroons:              macaroon.Slice{mac1},
			expectedMacaroonBase64: "AgJCAAABAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAgMAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEAAAGIHqWvcIDGguzG0xeNz7kxTr4IrPg64b0EjRonYD3zkVe",
		},
		"many": {
			macaroons:              macaroon.Slice{mac1, mac2},
			expectedMacaroonBase64: "AgJCAAABAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAgMAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEAAAGIHqWvcIDGguzG0xeNz7kxTr4IrPg64b0EjRonYD3zkVeAgJCAAABAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAgMAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAFAAAGIJL//w3j0KDNo5jUh+g47BAyhvsP7eiNYFHlPDw4Od/Z",
		},
		"defective": {
			macaroons:     macaroon.Slice{mac1, {}, mac2},
			expectedError: errors.New(`failed to marshal macaroon "": bad macaroon version v0`),
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			macaroonBase64, err := MarshalMacaroons(test.macaroons...)
			if !((err == nil) == (test.expectedError == nil)) || !(errors.Is(err, test.expectedError) || err.Error() == test.expectedError.Error()) {
				t.Fatalf("expected: %v but got: %v", test.expectedError, err)
			}

			if macaroonBase64 != test.expectedMacaroonBase64 {
				t.Errorf("expected: %v but got: %v", test.expectedMacaroonBase64, macaroonBase64)
			}
		})
	}
}

func TestUnmarshalMacaroons(t *testing.T) {
	mac1, _ := macaroon.New([]byte{1}, []byte{
		0, 0, // Version
		1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // Payment Hash
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2,
		3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // Id
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4}, "", macaroon.V2)
	mac2, _ := macaroon.New([]byte{1}, []byte{
		0, 0, // Version
		1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // Payment Hash
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2,
		3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // Id
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 5}, "", macaroon.V2)

	tests := map[string]struct {
		macaroonsBase64   string
		expectedMacaroons map[Identifier]*macaroon.Macaroon
		expectedError     error
	}{
		"no macaroons": { // macaroonsBase64 is guaranteed by authorizationMatcher to be a non empty string
			macaroonsBase64:   "",
			expectedMacaroons: map[Identifier]*macaroon.Macaroon{},
			expectedError:     nil,
		},
		"defective macaroon": {
			macaroonsBase64: "AGIAJEemVQUTEyNCR0exk7ek90Cg==",
			expectedError:   base64.CorruptInputError(28),
		},
		"one invalid macaroon": {
			macaroonsBase64: "MDAwZWxvY2F0aW9uIAowMDEwaWRlbnRpZmllciAKMDAyZnNpZ25hdHVyZSCPtT9UwdGWx8khvYJlWY9BhJu6JUG3in2Ef49M+/Oukgo=",
			expectedError:   ErrUnknownVersion(-1),
		},
		"one macaroon": {
			macaroonsBase64: "AgJCAAABAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAgMAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEAAAGIHqWvcIDGguzG0xeNz7kxTr4IrPg64b0EjRonYD3zkVe",
			expectedMacaroons: map[Identifier]*macaroon.Macaroon{
				{
					Version:     0,
					PaymentHash: [32]byte{1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2},
					ID:          [32]byte{3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4},
				}: mac1,
			},
		},
		"many defective macaroons": {
			macaroonsBase64: "AgJCAAABAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAgMAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEAAAGIHqWvcIDGguzG0xeNz7kxTr4IrPg64b0EjRonYD3zkVeAgJCAAABAAAAAAAAAAAAAAAAAAAAAAAAAA",
			expectedError:   errors.New("illegal base64 data at input byte 172"),
		},
		"many macaroons with comma": {
			macaroonsBase64: "AgJCAAABAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAgMAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEAAAGIHqWvcIDGguzG0xeNz7kxTr4IrPg64b0EjRonYD3zkVe,AgJCAAABAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAgMAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAFAAAGIJL//w3j0KDNo5jUh+g47BAyhvsP7eiNYFHlPDw4Od/Z",
			expectedMacaroons: map[Identifier]*macaroon.Macaroon{
				{
					Version:     0,
					PaymentHash: [32]byte{1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2},
					ID:          [32]byte{3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4},
				}: mac1,
				{
					Version:     0,
					PaymentHash: [32]byte{1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2},
					ID:          [32]byte{3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 5},
				}: mac2,
			},
		},
		"many macaroons": {
			macaroonsBase64: "AgJCAAABAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAgMAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEAAAGIHqWvcIDGguzG0xeNz7kxTr4IrPg64b0EjRonYD3zkVeAgJCAAABAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAgMAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAFAAAGIJL//w3j0KDNo5jUh+g47BAyhvsP7eiNYFHlPDw4Od/Z",
			expectedMacaroons: map[Identifier]*macaroon.Macaroon{
				{
					Version:     0,
					PaymentHash: [32]byte{1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2},
					ID:          [32]byte{3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4},
				}: mac1,
				{
					Version:     0,
					PaymentHash: [32]byte{1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2},
					ID:          [32]byte{3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 5},
				}: mac2,
			},
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			macaroons, err := UnmarshalMacaroons(test.macaroonsBase64)

			if !((err == nil) == (test.expectedError == nil)) || !(errors.Is(err, test.expectedError) || err.Error() == test.expectedError.Error()) {
				t.Fatalf("expected: %v but got: %v", test.expectedError, err)
			}

			if !reflect.DeepEqual(macaroons, test.expectedMacaroons) {
				t.Errorf("expected: %v but got: %v", test.expectedMacaroons, macaroons)
			}
		})
	}
}

func TestMarchalIdentifier(t *testing.T) {
	tests := map[string]struct {
		version            uint16
		paymentHash        Hash
		id                 ID
		expectedMacaroonId []byte
		expectedErr        error
	}{
		"invalid version": {
			version:     1,
			expectedErr: ErrUnknownVersion(1),
		},
		"success": {
			paymentHash: [BlockSize]byte{
				1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
				0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2,
			},
			id: [BlockSize]byte{
				3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
				0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4,
			},
			expectedMacaroonId: []byte{
				0, 0, // Version
				1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // Payment Hash
				0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2,
				3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // Id
				0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4,
			},
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			identifier := Identifier{
				Version:     test.version,
				PaymentHash: test.paymentHash,
				ID:          test.id,
			}

			macaroonID, err := MarchalIdentifier(identifier)

			if !errors.Is(err, test.expectedErr) {
				t.Fatalf("expected: %v but got: %v", test.expectedErr, err)
			}

			if !bytes.Equal(macaroonID, test.expectedMacaroonId) {
				t.Errorf("expected: %s but got: %s", test.expectedMacaroonId, macaroonID)
			}
		})
	}
}

func TestUnmarshalIdentifier(t *testing.T) {
	tests := map[string]struct {
		macaroonID          []byte
		expectedPaymentHash Hash
		expectedId          ID
		expectedErr         error
	}{
		"empty value": {
			macaroonID:  []byte{},
			expectedErr: ErrUnknownVersion(-1),
		},
		"malformed truncated value": {
			macaroonID: []byte{
				0, 0, // Version
				1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // Payment Hash
				0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2,
			},
			expectedErr: ErrUnknownVersion(-1),
		},
		"malformed extended value": {
			macaroonID: []byte{
				0, 0, // Version
				1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // Payment Hash
				0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2,
				3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // Id
				0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4,
				0, 5,
			},
			expectedErr: ErrUnknownVersion(-1),
		},
		"wrong version": {
			macaroonID: []byte{
				0, 2, // Version
				1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // Payment Hash
				0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2,
				3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // Id
				0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4,
			},
			expectedErr: ErrUnknownVersion(2),
		},
		"success": {
			macaroonID: []byte{
				0, 0, // Version
				1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // Payment Hash
				0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2,
				3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // Id
				0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4,
			},
			expectedPaymentHash: [BlockSize]byte{
				1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
				0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2,
			},
			expectedId: [BlockSize]byte{
				3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
				0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4,
			},
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			identifier, err := UnmarshalIdentifier(test.macaroonID)

			if !errors.Is(err, test.expectedErr) {
				t.Fatalf("expected: %v but got: %v", test.expectedErr, err)
			}

			if identifier.PaymentHash != test.expectedPaymentHash {
				t.Errorf("expected: %s but got: %s", test.expectedPaymentHash, identifier.PaymentHash)
			}

			if identifier.ID != test.expectedId {
				t.Errorf("expected:: %s but got: %s", test.expectedId, identifier.ID)
			}
		})
	}
}
