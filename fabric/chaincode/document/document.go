package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/hyperledger/fabric-contract-api-go/contractapi"
)

// DocumentContract exposes a deliberately append-only evidence registry.
type DocumentContract struct {
	contractapi.Contract
}

// DocumentRecord deliberately excludes the plaintext document, PQC public key,
// signature bytes, and KEM ciphertext. Those remain in the application store.
type DocumentRecord struct {
	DocumentID       string `json:"documentId"`
	DocumentHash     string `json:"documentHash"`
	SignatureDigest  string `json:"signatureDigest"`
	KeyFingerprint   string `json:"keyFingerprint"`
	SigningAlgorithm string `json:"signingAlgorithm"`
	KEMAlgorithm     string `json:"kemAlgorithm"`
	Issuer           string `json:"issuer"`
	SizeBytes        int    `json:"sizeBytes"`
	RegisteredAt     string `json:"registeredAt"`
	Status           string `json:"status"`
	RevokedAt        string `json:"revokedAt"`
	RevocationReason string `json:"revocationReason"`
}

func (c *DocumentContract) DocumentExists(ctx contractapi.TransactionContextInterface, documentID string) (bool, error) {
	data, err := ctx.GetStub().GetState(documentID)
	if err != nil {
		return false, fmt.Errorf("read document %q: %w", documentID, err)
	}
	return data != nil, nil
}

const (
	maxIssuerLength           = 160
	maxRevocationReasonLength = 500
)

func isSHA256Hex(value string) bool {
	if len(value) != 64 {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

func isDocumentID(value string) bool {
	if len(value) != 36 {
		return false
	}
	for i, r := range value {
		switch {
		case i == 8 || i == 13 || i == 18 || i == 23:
			if r != '-' {
				return false
			}
		case (r >= '0' && r <= '9') || (r >= 'a' && r <= 'f') || (r >= 'A' && r <= 'F'):
			// valid hexadecimal UUID character
		default:
			return false
		}
	}
	return true
}

func validateDocumentRecord(record DocumentRecord, documentID string) error {
	if !isDocumentID(documentID) || record.DocumentID != documentID {
		return fmt.Errorf("documentId must be a valid UUID and match the transaction argument")
	}
	if !isSHA256Hex(record.DocumentHash) {
		return fmt.Errorf("documentHash must be a 64-character SHA-256 hex value")
	}
	if !isSHA256Hex(record.SignatureDigest) {
		return fmt.Errorf("signatureDigest must be a 64-character SHA-256 hex value")
	}
	if !isSHA256Hex(record.KeyFingerprint) {
		return fmt.Errorf("keyFingerprint must be a 64-character SHA-256 hex value")
	}
	if record.SigningAlgorithm != "ML-DSA-65" {
		return fmt.Errorf("unsupported signing algorithm %q", record.SigningAlgorithm)
	}
	if record.KEMAlgorithm != "ML-KEM-768" {
		return fmt.Errorf("unsupported KEM algorithm %q", record.KEMAlgorithm)
	}
	if record.Issuer == "" || len(record.Issuer) > maxIssuerLength {
		return fmt.Errorf("issuer must be between 1 and %d characters", maxIssuerLength)
	}
	if record.SizeBytes <= 0 {
		return fmt.Errorf("sizeBytes must be greater than zero")
	}
	if record.Status != "REGISTERED" {
		return fmt.Errorf("new document record must have status REGISTERED")
	}
	return nil
}

// CreateDocument commits the initial proof record. The cryptographic evidence fields remain immutable; lifecycle status may be revoked through RevokeDocument.
func (c *DocumentContract) CreateDocument(ctx contractapi.TransactionContextInterface, documentID string, recordJSON string) error {
	exists, err := c.DocumentExists(ctx, documentID)
	if err != nil {
		return err
	}
	if exists {
		return fmt.Errorf("document %q already exists", documentID)
	}
	var record DocumentRecord
	if err := json.Unmarshal([]byte(recordJSON), &record); err != nil {
		return fmt.Errorf("invalid document record: %w", err)
	}
	if record.Status == "" {
		record.Status = "REGISTERED"
	}
	record.Issuer = strings.TrimSpace(record.Issuer)
	if err := validateDocumentRecord(record, documentID); err != nil {
		return err
	}
	if timestamp, timestampErr := ctx.GetStub().GetTxTimestamp(); timestampErr == nil && timestamp != nil {
		record.RegisteredAt = time.Unix(timestamp.Seconds, int64(timestamp.Nanos)).UTC().Format(time.RFC3339Nano)
	}
	encoded, err := json.Marshal(record)
	if err != nil {
		return fmt.Errorf("serialize document record: %w", err)
	}
	if err := ctx.GetStub().PutState(documentID, encoded); err != nil {
		return fmt.Errorf("write document record: %w", err)
	}
	return ctx.GetStub().SetEvent("DocumentRegistered", encoded)
}

// RevokeDocument preserves the original evidence while marking the record as revoked.
// Revocation is append-only from an audit perspective: the prior ledger state remains in Fabric history.
func (c *DocumentContract) RevokeDocument(ctx contractapi.TransactionContextInterface, documentID string, reason string) error {
	reason = strings.TrimSpace(reason)
	if reason == "" {
		return fmt.Errorf("revocation reason is required")
	}
	if len(reason) > maxRevocationReasonLength {
		return fmt.Errorf("revocation reason is too long")
	}
	record, err := c.ReadDocument(ctx, documentID)
	if err != nil {
		return err
	}
	if record.Status == "REVOKED" {
		return fmt.Errorf("document %q is already revoked", documentID)
	}
	record.Status = "REVOKED"
	record.RevocationReason = reason
	if timestamp, timestampErr := ctx.GetStub().GetTxTimestamp(); timestampErr == nil && timestamp != nil {
		record.RevokedAt = time.Unix(timestamp.Seconds, int64(timestamp.Nanos)).UTC().Format(time.RFC3339Nano)
	}
	encoded, err := json.Marshal(record)
	if err != nil {
		return fmt.Errorf("serialize revoked document record: %w", err)
	}
	if err := ctx.GetStub().PutState(documentID, encoded); err != nil {
		return fmt.Errorf("write revoked document record: %w", err)
	}
	return ctx.GetStub().SetEvent("DocumentRevoked", encoded)
}

func (c *DocumentContract) ReadDocument(ctx contractapi.TransactionContextInterface, documentID string) (*DocumentRecord, error) {
	data, err := ctx.GetStub().GetState(documentID)
	if err != nil {
		return nil, fmt.Errorf("read document %q: %w", documentID, err)
	}
	if data == nil {
		return nil, fmt.Errorf("document %q does not exist", documentID)
	}
	var record DocumentRecord
	if err := json.Unmarshal(data, &record); err != nil {
		return nil, fmt.Errorf("decode document %q: %w", documentID, err)
	}
	return &record, nil
}

func (c *DocumentContract) VerifyDocument(ctx contractapi.TransactionContextInterface, documentID string, documentHash string, signatureDigest string, keyFingerprint string) (bool, error) {
	record, err := c.ReadDocument(ctx, documentID)
	if err != nil {
		return false, err
	}
	return record.DocumentHash == documentHash && record.SignatureDigest == signatureDigest && record.KeyFingerprint == keyFingerprint, nil
}

func (c *DocumentContract) GetDocumentHistory(ctx contractapi.TransactionContextInterface, documentID string) ([]map[string]interface{}, error) {
	iterator, err := ctx.GetStub().GetHistoryForKey(documentID)
	if err != nil {
		return nil, fmt.Errorf("history for %q: %w", documentID, err)
	}
	defer iterator.Close()

	var history []map[string]interface{}
	for iterator.HasNext() {
		entry, nextErr := iterator.Next()
		if nextErr != nil {
			return nil, nextErr
		}
		history = append(history, map[string]interface{}{
			"transactionId": entry.TxId,
			"isDelete":      entry.IsDelete,
			"value":         json.RawMessage(entry.Value),
		})
	}
	return history, nil
}

func main() {
	chaincode, err := contractapi.NewChaincode(&DocumentContract{})
	if err != nil {
		panic(fmt.Sprintf("create document chaincode: %v", err))
	}
	if err := chaincode.Start(); err != nil {
		panic(fmt.Sprintf("start document chaincode: %v", err))
	}
}
