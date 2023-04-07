package cipher

import (
	"strings"
	"testing"

	"github.com/hashicorp/vault/api"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var cipherClient *Client

func init() {
	// Create a new cipher client
	var err error
	cipherClient, err = NewClientWithToken("myroot", "http://localhost:8200")
	if err != nil {
		panic(err)
	}

	err = cipherClient.vaultClient.Sys().Mount("transit", &api.MountInput{Type: "transit"})
	if err != nil {
		panic(err)
	}
}

func TestClient_Encrypt_Decrypt(t *testing.T) {
	type Person struct {
		Name    string `encrypted:"true"`
		Address string `encrypted:"true"`
		Age     int    `encrypted:"true"`
		Desc    string
	}
	encryptionKey := "my-encryption-key"
	p := &Person{Name: "John Doe", Address: "123 Main St", Age: 30, Desc: "abc"}

	// encrypt the struct
	err := cipherClient.Encrypt(p, encryptionKey)
	require.NoError(t, err)

	// assert that the encrypted struct has the expected values
	expected := &Person{Name: "", Address: "", Age: 30, Desc: "abc"}
	assert.True(t, strings.HasPrefix(p.Name, "vault:v1:"), "expected encrypted name to start with vault:v1:")
	assert.True(t, strings.HasPrefix(p.Address, "vault:v1:"), "expected encrypted address to start with vault:v1:")
	assert.Equal(t, expected.Age, p.Age, "expected age to be not encrypted")
	assert.Equal(t, expected.Desc, p.Desc, "expected desc to be not encrypted")
	assert.NotEqual(t, expected, p)

	// Decrypt the struct
	err = cipherClient.Decrypt(p, encryptionKey)
	require.NoError(t, err)

	// assert that the decrypted struct has the expected values
	expected = &Person{Name: "John Doe", Address: "123 Main St", Age: 30, Desc: "abc"}
	assert.Equal(t, expected, p)
}
