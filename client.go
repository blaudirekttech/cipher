package cipher

import (
	"encoding/base64"
	"errors"
	"fmt"
	"reflect"

	vault "github.com/hashicorp/vault/api"
)

type Client struct {
	vaultClient *vault.Client
}

// NewClientWithToken creates a new cipher client with a vault token.
// It returns a pointer to a Client and an error.
func NewClientWithToken(token, addr string) (*Client, error) {
	config := vault.DefaultConfig()
	config.Address = addr
	client, err := vault.NewClient(config)
	if err != nil {
		return nil, err
	}
	client.SetToken(token)
	return &Client{vaultClient: client}, nil
}

// Encrypt encrypts the first level fields of the given object with the provided encryption key.
// The encrypted fields must be of type string and have the "encrypted" tag set to true.
// It returns an error if the encryption fails.
func (c *Client) Encrypt(obj any, encryptionKey string) error {
	if encryptionKey == "" {
		return errors.New("encryption key is empty")
	}

	// Make a pointer to the obj and use Elem() to get the addressable value.
	ptr := reflect.ValueOf(obj)
	if ptr.Kind() != reflect.Ptr {
		return errors.New("obj must be a pointer")
	}
	value := ptr.Elem()

	// Get all encrypted first level fields.
	fields := getEncryptedFields(value.Interface())
	if len(fields) <= 0 {
		return nil
	}

	var batchInput []map[string]any
	for _, field := range fields {
		batchInput = append(batchInput, map[string]any{
			"plaintext": []byte(value.FieldByName(field.Name).String()),
			"reference": []byte(field.Name),
		})
	}

	request := map[string]any{
		"batch_input": batchInput,
	}

	transitPath := fmt.Sprintf("transit/encrypt/%s", encryptionKey)
	res, err := c.vaultClient.Logical().Write(transitPath, request)
	if err != nil {
		return err
	}

	results, ok := res.Data["batch_results"].([]any)
	if !ok {
		return errors.New("batch_results not found in the response data")
	}
	for _, result := range results {
		batchResult, ok := result.(map[string]any)
		if !ok {
			return errors.New("invalid batch result")
		}
		reference, err := base64.StdEncoding.DecodeString(batchResult["reference"].(string))
		if err != nil {
			return err
		}
		value.FieldByName(string(reference)).SetString(batchResult["ciphertext"].(string))
	}

	return nil
}

// Decrypt decrypts the first level fields of the given object with the provided encryption key.
// The encrypted fields must be of type string and have the "encrypted" tag set to true.
// It returns an error if the decryption fails.
func (c *Client) Decrypt(obj any, encryptionKey string) error {
	if encryptionKey == "" {
		return errors.New("encryption key is empty")
	}

	// Make a pointer to the obj and use Elem() to get the addressable value
	ptr := reflect.ValueOf(obj)
	if ptr.Kind() != reflect.Ptr {
		return errors.New("obj must be a pointer")
	}
	value := ptr.Elem()

	// get all encrypted first level fields
	fields := getEncryptedFields(value.Interface())
	if len(fields) <= 0 {
		return nil
	}

	var batchInput []map[string]any
	for _, field := range fields {
		batchInput = append(batchInput, map[string]any{
			"ciphertext": value.FieldByName(field.Name).String(),
			"reference":  field.Name,
		})
	}

	request := map[string]any{
		"batch_input": batchInput,
	}

	transitPath := fmt.Sprintf("transit/decrypt/%s", encryptionKey)
	res, err := c.vaultClient.Logical().Write(transitPath, request)
	if err != nil {
		return err
	}

	results := res.Data["batch_results"].([]any)
	results, ok := res.Data["batch_results"].([]any)
	if !ok {
		return errors.New("batch_results not found in the response data")
	}
	for _, result := range results {
		batchResult := result.(map[string]any)
		batchResult, ok := result.(map[string]any)
		if !ok {
			return errors.New("invalid batch result")
		}

		reference := batchResult["reference"].(string)
		val, err := base64.StdEncoding.DecodeString(batchResult["plaintext"].(string))
		if err != nil {
			return err
		}
		value.FieldByName(reference).SetString(string(val))
	}

	return nil
}

// getEncryptedFields returns all fields of type "string" with the encrypted tag on the given struct
// Nested Structs are not supported due to performance and complexity reasons
func getEncryptedFields(s any) []reflect.StructField {
	var encryptedFields []reflect.StructField
	st := reflect.TypeOf(s)

	for i := 0; i < st.NumField(); i++ {
		field := st.Field(i)
		tag := field.Tag.Get("encrypted")
		if tag == "true" && field.Type == reflect.TypeOf("string") {
			encryptedFields = append(encryptedFields, field)
		}
	}

	return encryptedFields
}
