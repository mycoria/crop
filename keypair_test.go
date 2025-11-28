package crop

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

var signTestData = []byte("The quick brown fox jumps over the lazy dog.")

func TestKeyPair(t *testing.T) {
	for _, kpType := range AllKeyPairTypes() {
		t.Run(string(kpType), func(t *testing.T) {
			// Generate and types.
			priv, err := kpType.New()
			if err != nil {
				t.Fatal(err)
			}
			if !priv.HasPrivate() {
				t.Fatal("new key has no private")
			}
			pub := priv.ToPublic()
			if pub.HasPrivate() {
				t.Fatal("pubkey has private")
			}

			// Sign and verify.
			sig, err := priv.Sign(signTestData)
			if err != nil {
				t.Fatal(err)
			}
			err = pub.Verify(signTestData, sig)
			if err != nil {
				t.Fatal(err)
			}

			// Import / Export.

			// Export private key.
			privExport, err := priv.Export()
			if err != nil {
				t.Fatal(err)
			}
			privText := privExport.Text()
			privBytes, err := privExport.Bytes()
			if err != nil {
				t.Fatal(err)
			}
			fmt.Println(privText)

			// Import private key.
			privImportText, err := LoadKeyFromText(privText)
			if err != nil {
				t.Fatal(err)
			}
			privImportBytes, err := LoadKeyFromBytes(privBytes)
			if err != nil {
				t.Fatal(err)
			}
			assert.Equal(t, privImportText, privImportBytes, "imports must match")
			importedPriv, err := LoadKeyPair(privImportText)
			if err != nil {
				t.Fatal(err)
			}
			assert.EqualExportedValues(t, priv, importedPriv)

			// Export public key.
			pubExport, err := pub.Export()
			if err != nil {
				t.Fatal(err)
			}
			pubText := pubExport.Text()
			pubBytes, err := pubExport.Bytes()
			if err != nil {
				t.Fatal(err)
			}
			fmt.Println(pubText)

			// Import public key.
			pubImportText, err := LoadKeyFromText(pubText)
			if err != nil {
				t.Fatal(err)
			}
			pubImportBytes, err := LoadKeyFromBytes(pubBytes)
			if err != nil {
				t.Fatal(err)
			}
			assert.Equal(t, pubImportText, pubImportBytes, "imports must match")
			importedpub, err := LoadKeyPair(pubImportText)
			if err != nil {
				t.Fatal(err)
			}
			assert.EqualExportedValues(t, pub, importedpub)
		})
	}
}
