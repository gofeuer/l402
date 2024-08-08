# L402 Core - HTTP 402 Library for Lightning Payments
[![Release Version](https://img.shields.io/github/release/gofeuer/l402.svg)](https://github.com/gofeuer/l402/releases)
![GitHub go.mod Go version](https://img.shields.io/github/go-mod/go-version/gofeuer/l402)
![macaroon.v2](https://img.shields.io/badge/dependency_count-1-blue)
![GitHub Actions Workflow Status](https://img.shields.io/github/actions/workflow/status/gofeuer/l402/golangci-lint.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/gofeuer/l402)](https://goreportcard.com/report/github.com/gofeuer/l402)
![Lightning Network](https://img.shields.io/badge/bitcoin-lightning_network-792EE5)
[![Donate Bitcoin on chain](https://img.shields.io/badge/donate-bitcoin-F7931A?logo=bitcoin)](https://www.bitcoinqrcodemaker.com/pay/?type=1&style=bitcoin&address=bc1qanlngx9pfm2pkszm7lx88wp2qa6eh9juuskpl0e5a00edslhe89qtdejr0)

Inspired by the HTTP 402 Payment Required status code, L402 introduces a novel approach to secure access and dynamic pricing. Whether you’re building a subscription-based platform, a content delivery service, or an API, L402 empowers you to seamlessly integrate payments using the Lightning Network.

L402 Core is a library that bridges the gap between web services, authentication, and payments. 

## L402 Proxy Middleware

A middleware to secure your endpoints.

```go
import "github.com/gofeuer/l402"

func main() {
	minter := YourMacaroonMinter{}      // Your l402.MacaroonMinter implementation
	authorizer := YourAccessAuthority{} // Your l402.AccessAuthority implementation

	// Create a L402 proxy by passing a l402.MacaroonMinter and a l402.AccessAuthority
	proxy := l402.Proxy(minter, authorizer)

	// Use `proxy` as a middleware to endpoints that require payment
	http.Handle("GET /", proxy(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "premium content")
	})))

	http.ListenAndServe(":8080", http.DefaultServeMux)
}
```

## Features

- **HTTP 402 Integration:** L402 leverages the HTTP 402 status code to signal that payment is required to access a resource. Say goodbye to traditional paywalls; L402 brings a more elegant solution.

- **Macaroons for Authorization:** We’ve baked in macaroons! These delightful authorization tokens allow you to package attributes and capabilities alongside your payment request. Dynamic pricing? Check. Automated tier upgrades? Absolutely.

- **Lightning Network Magic:** L402 dances with the Lightning Network. Users pay for services over Lightning, and in return, they receive preimages-cryptographic keys that unlock access. It’s like a secret handshake, but with satoshis.

## Components

To use L402 Core you need to provide the L402 middleware a couple of components:

### An implementation of `l402.MacaroonMinter`

The minter is used by the authorization handler to provide the user a new set of macaroons and an invoice.

```go
type YourMacaroonMinter struct {
	// connection to a lighting node
	// key storage for macaroon rootKeys
}

func (m YourMacaroonMinter) MintWithChallenge(r *http.Request) (string, l402.Challenge, error) {
	var paymentHash [32]byte
	var id [32]byte

	// A l402.Identifier is encoded and used as the macaroon's ID
	macaroonID, _ := l402.MarchalIdentifier(l402.Identifier{
		PaymentHash: paymentHash, // Hash of the secret revealed by paying the invoice
		ID:          id,          // An unique ID assigned to this macaroon
	})

	rootKey := []byte("{secret_key}") // A secret key that is used to singn and verify your macaroons

	// Create a macaroon that when paid gives access to the resouce requested by: (r *http.Request)
	mac, _ := macaroon.New(rootKey, macaroonID, "", macaroon.LatestVersion)

	macaroonsBase64, _ := l402.MarshalMacaroons(mac) // Accepts multiple macaroons

	// Provide an invoice from your Lighting node that reveals the secret matching paymentHash
	challenge := l402.Invoice("lnbc20m1pvjluezpp5q...")

	return macaroonsBase64, challenge, nil
}
```

### An implementation of `l402.AccessAuthority`

The L402 middleware uses the access authority to determine if a request should be proxied.

```go
type YourAccessAuthority struct {
	// key storage for macaroon rootKeys
}

func (m YourAccessAuthority) ApproveAccess(r *http.Request, macaroons map[l402.Identifier]*macaroon.Macaroon) l402.Rejection {
	for identifier, macaroon := range macaroons {
		// Verify if macaroon is signed by the correct rootKey
	}

	// Here you should determine if the received macarons give access to the resouce requested by: (r *http.Request)

	// Return nil if the request is approved
	return errors.New("{rejection reason}")
}
```

### Contributing
Pull requests are welcome! If you have ideas for enhancing L402 Core, feel free to fork the repo and submit your changes.


**L402** | Because paying for content should be as smooth as a Lightning bolt. ⚡️🌐
