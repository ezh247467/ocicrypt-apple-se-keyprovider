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
	"fmt"
	"io"
	"log"
	"net/url"
	"os"

	"github.com/containers/ocicrypt/keywrap/keyprovider"
	"golang.org/x/crypto/hkdf"
)

const seCryptName = "apple-se"

type annotationPacket struct {
	KeyUrl            string `json:"KeyUrl"`
	EphPub            []byte `json:"EphPub"`
	WrappedKey        []byte `json:"WrappedKey"`
	WrapType          string `json:"WrapType"`
}

func main() {
	var input keyprovider.KeyProviderKeyWrapProtocolInput
	err := json.NewDecoder(os.Stdin).Decode(&input)
	if err != nil {
		log.Fatalf("Error decoding ocicrypt input %v\n", err)
	}

	if input.Operation == keyprovider.OpKeyWrap {
		b, err := WrapKey(input)
		if err != nil {
			log.Fatalf("Error wrapping key %v\n", err)
		}
		fmt.Printf("%s", b)
	} else if input.Operation == keyprovider.OpKeyUnwrap {
		b, err := UnwrapKey(input)
		if err != nil {
			log.Fatalf("Error unwrapping key %v\n", err)
		}
		fmt.Printf("%s", b)
	} else {
		log.Fatalf("Operation %v not recognized", input.Operation)
	}
}

func WrapKey(keyP keyprovider.KeyProviderKeyWrapProtocolInput) ([]byte, error) {
	_, ok := keyP.KeyWrapParams.Ec.Parameters[seCryptName]
	if !ok {
		return nil, fmt.Errorf("provider must be formatted as provider:apple-se:apple-se://se?mode=encrypt&pub=base64(pubkey) not set, got %s", keyP.KeyWrapParams.Ec.Parameters[seCryptName])
	}

	if len(keyP.KeyWrapParams.Ec.Parameters[seCryptName]) == 0 {
		return nil, fmt.Errorf("provider must be formatted as provider:apple-se:apple-se://se?mode=encrypt&pub=base64(pubkey) got %s", keyP.KeyWrapParams.Ec.Parameters[seCryptName])
	}

	seURI := keyP.KeyWrapParams.Ec.Parameters[seCryptName][0]
	u, err := url.Parse(string(seURI))
	if err != nil {
		return nil, fmt.Errorf("error parsing Provider URL must be  provider:apple-se:apple-se://se?mode=encrypt&pub=base64(pubkey) got %s", seURI)
	}
	if u.Scheme != seCryptName {
		return nil, fmt.Errorf("error parsing Provider URL: unrecognized scheme got %s", u.Scheme)
	}

	m, err := url.ParseQuery(u.RawQuery)
	if err != nil {
		return nil, fmt.Errorf("error parsing Provider URL: %v", err)
	}

	if m["mode"] == nil {
		return nil, errors.New("error: mode=encrypt value must be set")
	}
	if m["mode"][0] != "encrypt" {
		return nil, errors.New("error: mode=encrypt value must be set")
	}

	if m["pub"] == nil {
		return nil, errors.New("error: pub value must be set")
	}
	pubData, err := base64.URLEncoding.DecodeString(m["pub"][0])
	if err != nil {
		log.Fatalf("Error decoding pubkey: %v, %s, %s", err, m["pub"][0], string(seURI))
	}

	// Parse raw public key data (uncompressed EC point)
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

	// ECIES: Generate ephemeral keypair (P-256) for Diffie-Hellman key agreement
	ephPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Fatalf("failed to generate ephemeral EC key: %v", err)
	}

	ephPubBytes := elliptic.Marshal(elliptic.P256(), ephPriv.PublicKey.X, ephPriv.PublicKey.Y)

	// ECDH: Compute shared secret using ephPriv and ecPub
	raw, _ := ecPub.Curve.ScalarMult(ecPub.X, ecPub.Y, ephPriv.D.Bytes())
	sharedSecret := raw.Bytes()

	// Derive session key (wrappingKey) from shared secret via HKDF-SHA256
	hkdfReader := hkdf.New(sha256.New, sharedSecret, nil, nil)
	wrappingKey := make([]byte, 32)
	if _, err := io.ReadFull(hkdfReader, wrappingKey); err != nil {
		log.Fatalf("hkdf failed: %v", err)
	}

	// Encrypt the CEK with session key (AES-GCM)
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
		WrapType:          "AES-GCM",
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

func UnwrapKey(keyP keyprovider.KeyProviderKeyWrapProtocolInput) ([]byte, error) {
	apkt := annotationPacket{}
	err := json.Unmarshal(keyP.KeyUnwrapParams.Annotation, &apkt)
	if err != nil {
		return nil, err
	}

	// Extract the ephemeral public key and wrapped CEK from the annotation packet
	ephPub := apkt.EphPub
	ciphertext := apkt.WrappedKey

	_, ok := keyP.KeyUnwrapParams.Dc.Parameters[seCryptName]
	if !ok {
		return nil, errors.New("provider must be formatted as provider:apple-se:apple-se://se?mode=decrypt")
	}

	if len(keyP.KeyUnwrapParams.Dc.Parameters[seCryptName]) == 0 {
		return nil, errors.New("provider must be formatted as  provider:apple-se:apple-se://se?mode=decrypt")
	}

	seURI := keyP.KeyUnwrapParams.Dc.Parameters[seCryptName][0]

	u, err := url.Parse(string(seURI))
	if err != nil {
		return nil, fmt.Errorf("error parsing Provider URL must be provider:apple-se:apple-se://se?mode=decrypt got %s", seURI)
	}
	if u.Scheme != seCryptName {
		return nil, fmt.Errorf("error parsing Provider URL: unrecognized scheme got %s", u.Scheme)
	}
	m, err := url.ParseQuery(u.RawQuery)
	if err != nil {
		return nil, fmt.Errorf("error parsing Provider URL: %v", err)
	}
	if m["mode"] == nil {
		return nil, errors.New("error: mode must be set for decryption")
	}
	if m["mode"][0] != "decrypt" {
		return nil, errors.New("error: mode must set to decrypt")
	}

	// Derive AES session key the ephemeral public key and the private key in SE
	sessionKey, err := DeriveAESKeyFromSE(ephPub);
	if err != nil {
		log.Fatalf("DeriveAESKeyFromSE failed: %v", err)
	}

	// Decrypt the CEK with the session key (AES-GCM)
	c, err := aes.NewCipher(sessionKey)
	if err != nil {
		return nil, fmt.Errorf("unable to create AES Cipher data: %v", err)
	}
	gcm, err := cipher.NewGCM(c)
	if err != nil {
		return nil, fmt.Errorf("unable to create GCM: %v", err)
	}
	nonceSize := gcm.NonceSize()
	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	unwrappedKey, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("unable to decrypt with GCM: %v", err)
	}
	return json.Marshal(keyprovider.KeyProviderKeyWrapProtocolOutput{
		KeyUnwrapResults: keyprovider.KeyUnwrapResults{OptsData: unwrappedKey},
	})
}

func DeriveAESKeyFromSE(ephPub []byte) ([]byte, error) {
    out := make([]byte, 32)
    outLen := C.size_t(len(out))

	// Compute raw ECDH shared secret using private key in SE and ephPub
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