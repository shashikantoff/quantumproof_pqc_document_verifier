package main

import "testing"

func validTestRecord() DocumentRecord {
	return DocumentRecord{
		DocumentID:       "3e86ad70-27a0-40d7-92c7-ee287f27efcf",
		DocumentHash:     "396f25e420f9af65f236471eca99fc594308c4e0cbccd76b098594c6c36d96ff",
		SignatureDigest:  "a7296db5c770e7f90a47c26f6f708d183b214b3a36da0c77a012ad5fad025935",
		KeyFingerprint:   "1c5c00ad474823a2e51603798b9bc11141855a219b381996aa7da20c0283c856",
		SigningAlgorithm: "ML-DSA-65",
		KEMAlgorithm:     "ML-KEM-768",
		Issuer:           "University Issuing Authority",
		SizeBytes:        1024,
		Status:           "REGISTERED",
	}
}

func TestValidateDocumentRecordAcceptsValidRecord(t *testing.T) {
	record := validTestRecord()
	if err := validateDocumentRecord(record, record.DocumentID); err != nil {
		t.Fatalf("expected valid record, got error: %v", err)
	}
}

func TestValidateDocumentRecordRejectsInvalidHash(t *testing.T) {
	record := validTestRecord()
	record.DocumentHash = "not-a-sha256"
	if err := validateDocumentRecord(record, record.DocumentID); err == nil {
		t.Fatal("expected invalid document hash to be rejected")
	}
}

func TestValidateDocumentRecordRejectsUnsupportedAlgorithms(t *testing.T) {
	record := validTestRecord()
	record.SigningAlgorithm = "DEVELOPMENT-ED25519"
	if err := validateDocumentRecord(record, record.DocumentID); err == nil {
		t.Fatal("expected unsupported signing algorithm to be rejected")
	}
}

func TestValidateDocumentRecordRejectsInvalidDocumentID(t *testing.T) {
	record := validTestRecord()
	record.DocumentID = "document-1"
	if err := validateDocumentRecord(record, record.DocumentID); err == nil {
		t.Fatal("expected invalid document ID to be rejected")
	}
}

func TestValidateDocumentRecordRejectsOversizedIssuer(t *testing.T) {
	record := validTestRecord()
	record.Issuer = "x" + string(make([]byte, maxIssuerLength))
	if err := validateDocumentRecord(record, record.DocumentID); err == nil {
		t.Fatal("expected oversized issuer to be rejected")
	}
}
