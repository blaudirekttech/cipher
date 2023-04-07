# cipher

`cipher` is a Go package for encrypting and decrypting strings using [HashiCorp Vault's Transit Secret Engine](https://www.vaultproject.io/docs/secrets/transit/index.html).

## Prerequisites

Before using this package, make sure you have the following:

- A running instance of [HashiCorp Vault](https://www.vaultproject.io/) with Transit Secret Engine enabled.
- A valid Vault token with access to the Transit Secret Engine.
- Go version 1.20 or later installed.

_You can run a dev instance of Vault in docker using the following command:_

```bash
docker run --name vault --cap-add=IPC_LOCK -e 'VAULT_DEV_ROOT_TOKEN_ID=myroot' -e 'VAULT_DEV_LISTEN_ADDRESS=0.0.0.0:8200' -p 8200:8200 -d vault:latest
```

## Usage

To use `cipher`, follow these steps:

1. Import the `cipher` package.

```go
import "github.com/ruukydev/cipher"
```

2. Create a new `cipher.Client` with a Vault token and address.

```go
client, err := cipher.NewClientWithToken("your_vault_token", "http://localhost:8200")
if err != nil {
    // handle error
}
```

3. Define a struct with fields that need to be encrypted/decrypted.

```go
type Person struct {
    Name     string `encrypted:"true"`
    Address  string `encrypted:"true"`
    Phone    string
}
```

4. Initialize an instance of the struct and set values to the fields.

```go
p := &Person{
    Name:    "John Doe",
    Address: "123 Main St",
    Phone:   "555-1234",
}
```

5. Encrypt the struct fields using `client.Encrypt()` method.

```go
err = client.Encrypt(p, "my-encryption-key")
if err != nil {
    // handle error
}
```

6. Decrypt the struct fields using `client.Decrypt()` method.

```go
err = client.Decrypt(p, "my-encryption-key")
if err != nil {
    // handle error
}
```

7. The encrypted fields are now decrypted and can be accessed like regular struct fields.

```go
fmt.Printf("%+v\n", p)
// Output: &{Name:John Doe Address:123 Main St Phone:555-1234}
```

## Limitations

- Only first-level fields of the struct are encrypted/decrypted. Nested structs are not supported.
- Encrypted fields must be of type `string`.
- The `encrypted` tag must be set to `true` for the fields that need to be encrypted/decrypted.
- The `cipher` package uses the `encoding/base64` package to encode and decode ciphertext and plaintext. If you need to store non-ASCII characters, you should use a different encoding.