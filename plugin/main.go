package main

/*
#cgo CFLAGS: -I.
#cgo LDFLAGS: -framework Security -framework CoreFoundation
#include "se_helper.h"
*/
import "C"
import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net/url"

	"github.com/containers/ocicrypt/keywrap/keyprovider"
	"golang.org/x/crypto/hkdf"
)

func DeriveAESKeyFromSE(ephPub []byte) ([]byte, error) {
    out := make([]byte, 32)
    outLen := C.size_t(len(out))

    res := C.se_ecdh_shared_secret(
        (*C.uint8_t)(&ephPub[0]), C.size_t(len(ephPub)),
        (*C.uint8_t)(&out[0]), &outLen,
    )
    if res != 0 {
        return nil, fmt.Errorf("se_ecdh_shared_secret failed: %d", res)
    }

    // Run HKDF-SHA256 to derive AES key from raw shared secret
    hkdfReader := hkdf.New(sha256.New, out[:outLen], nil, nil)
    aesKey := make([]byte, 32)
    if _, err := io.ReadFull(hkdfReader, aesKey); err != nil {
        return nil, fmt.Errorf("hkdf derive failed: %v", err)
    }

    return aesKey, nil
}

func main() {
	pubkey := flag.String("pubkey", "", "base64 of PEM encoded P-256 public key")
	flag.Parse()
	pubData, err := base64.StdEncoding.DecodeString(*pubkey)
	if err != nil {
		log.Fatalf("Error decoding pubkey: %v", err)
	}

	curve := elliptic.P256()
    x, y := elliptic.Unmarshal(curve, pubData)
    if x == nil {
        log.Fatal("failed to unmarshal EC point")
    }

    ecPub := &ecdsa.PublicKey{
        Curve: curve,
        X:     x,
        Y:     y,
    }

	// ECIES: generate ephemeral keypair (P-256)
	ephPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Fatalf("failed to generate ephemeral EC key: %v", err)
	}

	ephPubBytes := elliptic.Marshal(elliptic.P256(), ephPriv.PublicKey.X, ephPriv.PublicKey.Y)

	// ECDH: compute shared secret
	raw, _ := ecPub.Curve.ScalarMult(ecPub.X, ecPub.Y, ephPriv.D.Bytes())
	sharedSecret := raw.Bytes()

	// Derive wrapping key from sharedSecret via HKDF-SHA256
	hkdfReader := hkdf.New(sha256.New, sharedSecret, nil, nil)
	wrappingKey := make([]byte, 32)
	if _, err := io.ReadFull(hkdfReader, wrappingKey); err != nil {
		log.Fatalf("hkdf failed: %v", err)
	}

	otherkey, err := DeriveAESKeyFromSE(ephPubBytes);
	if err != nil {
		log.Fatalf("DeriveAESKeyFromSE failed: %v", err)
	}
	
	fmt.Printf("wrappingKey: %x\n", wrappingKey)
	fmt.Printf("otherkey:   %x\n", otherkey)
}

const seCryptName = "apple-se"

type annotationPacket struct {
	KeyUrl            string `json:"KeyUrl"`
	EphPub            []byte `json:"EphPub"`
	WrappedKey        []byte `json:"WrappedKey"`
	WrapType          string `json:"WrapType"`
	KDF               string `json:"KDF,omitempty"`
}

func WrapKey(keyP keyprovider.KeyProviderKeyWrapProtocolInput) ([]byte, error) {
	_, ok := keyP.KeyWrapParams.Ec.Parameters[seCryptName]
	if !ok {
		return nil, fmt.Errorf("Provider must be formatted as provider:apple-se:apple-se://ek?mode=encrypt&pub=base64(pub_key) not set, got %s", keyP.KeyWrapParams.Ec.Parameters[seCryptName])
	}

	if len(keyP.KeyWrapParams.Ec.Parameters[seCryptName]) == 0 {
		return nil, fmt.Errorf("Provider must be formatted as provider:apple-se:apple-se://ek?mode=encrypt&pub=base64(pub_key) got %s", keyP.KeyWrapParams.Ec.Parameters[seCryptName])
	}

	seURI := keyP.KeyWrapParams.Ec.Parameters[seCryptName][0]
	u, err := url.Parse(string(seURI))
	if err != nil {
		return nil, fmt.Errorf("Error parsing Provider URL must be  provider:apple-se:apple-se://ek?mode=encrypt&pub=base64(pub_key) got %s", seURI)
	}
	if u.Scheme != seCryptName {
		return nil, fmt.Errorf("Error parsing Provider URL: unrecognized scheme got %s", u.Scheme)
	}

	m, err := url.ParseQuery(u.RawQuery)
	if err != nil {
		return nil, fmt.Errorf("Error parsing Provider URL: %v", err)
	}

	if m["mode"] == nil {
		return nil, errors.New("Error  mode=encrypt value must be set")
	}
	if m["mode"][0] != "encrypt" {
		return nil, errors.New("Error  mode=encrypt value must be set")
	}

	if m["pub"] == nil {
		return nil, errors.New("Error  /pub/ value must be set")
	}
	pubData, err := base64.StdEncoding.DecodeString(m["pub"][0])
	if err != nil {
		log.Fatalf("Error decoding pubkey: %v", err)
	}

	curve := elliptic.P256()
    x, y := elliptic.Unmarshal(curve, pubData)
    if x == nil {
        log.Fatal("failed to unmarshal EC point")
    }

    ecPub := &ecdsa.PublicKey{
        Curve: curve,
        X:     x,
        Y:     y,
    }

	// ECIES: generate ephemeral keypair (P-256)
	ephPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Fatalf("failed to generate ephemeral EC key: %v", err)
	}

	ephPubBytes := elliptic.Marshal(elliptic.P256(), ephPriv.PublicKey.X, ephPriv.PublicKey.Y)

	// ECDH: compute shared secret
	raw, _ := ecPub.Curve.ScalarMult(ecPub.X, ecPub.Y, ephPriv.D.Bytes())
	sharedSecret := raw.Bytes()

	// Derive wrapping key from sharedSecret via HKDF-SHA256
	hkdfReader := hkdf.New(sha256.New, sharedSecret, nil, nil)
	wrappingKey := make([]byte, 32)
	if _, err := io.ReadFull(hkdfReader, wrappingKey); err != nil {
		log.Fatalf("hkdf failed: %v", err)
	}

	// Encrypt the CEK with wrappingKey (AES-GCM)
	block, err := aes.NewCipher(wrappingKey)
	if err != nil {
		return nil, fmt.Errorf("creating AES cipher: %v", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("creating GCM: %v", err)
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("reading nonce: %v", err)
	}
	wrappedCEK := gcm.Seal(nonce, nonce, keyP.KeyWrapParams.OptsData, nil)

	ann := annotationPacket{
		KeyUrl:            string(seURI),
		EphPub:            ephPubBytes,
		WrappedKey:        wrappedCEK,
		WrapType:          "ECIES",
		KDF:               "HKDF-SHA256",
	}

	annJSON, err := json.Marshal(ann)
	if err != nil {
		return nil, fmt.Errorf("error encoding annotation JSON: %v", err)
	}

	return json.Marshal(keyprovider.KeyProviderKeyWrapProtocolOutput{
		KeyWrapResults: keyprovider.KeyWrapResults{
			Annotation: annJSON,
		},
	})
}