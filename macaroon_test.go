package l402

import (
	"bytes"
	"errors"
	"testing"
)

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
			expectedErr: ErrUnknownVersion,
		},
		"success": {
			paymentHash: [32]byte{
				1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
				0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2,
			},
			id: [32]byte{
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
				Id:          test.id,
			}

			macaroonID, err := MarchalIdentifier(identifier)

			if !errors.Is(err, test.expectedErr) {
				t.Errorf("test failed: expected err: %v but got %v", test.expectedErr, err)
			}

			if !bytes.Equal(macaroonID, test.expectedMacaroonId) {
				t.Errorf("test failed: expected macaroonID: %s but got %s", test.expectedMacaroonId, macaroonID)
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
		"invalid version": {
			macaroonID:  []byte{0, 2},
			expectedErr: ErrUnknownVersion,
		},
		"success": {
			macaroonID: []byte{
				0, 0, // Version
				1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // Payment Hash
				0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2,
				3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // Id
				0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4,
			},
			expectedPaymentHash: [32]byte{
				1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
				0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2,
			},
			expectedId: [32]byte{
				3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
				0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4,
			},
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			identifier, err := UnmarshalIdentifier(test.macaroonID)

			if !errors.Is(err, test.expectedErr) {
				t.Errorf("test failed: expected err: %v but got %v", test.expectedErr, err)
			}

			if identifier.PaymentHash != test.expectedPaymentHash {
				t.Errorf("test failed: expected PaymentHash: %s but got %s", test.expectedPaymentHash, identifier.PaymentHash)
			}

			if identifier.Id != test.expectedId {
				t.Errorf("test failed: expected ID: %s but got %s", test.expectedId, identifier.Id)
			}
		})
	}
}
