package main

import (
	"bytes"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	opb "github.com/appsworld/katalinaware/protos"
)

const appleNotarizationAPI = "https://api.apple-cloudkit.com/database/1/com.apple.gk.ticket-delivery/production/public/records/lookup"

type NotarizationRequest struct {
	Records map[string]interface{} `json:"records"`
}

type NotarizationResponse struct {
	Records []NotarizationRecord `json:"records"`
}

type NotarizationRecord struct {
	RecordName      string                 `json:"recordName"`
	RecordType      string                 `json:"recordType,omitempty"`
	Fields          map[string]interface{} `json:"fields,omitempty"`
	Reason          string                 `json:"reason,omitempty"`
	ServerErrorCode string                 `json:"serverErrorCode,omitempty"`
	Created         *NotarizationTimestamp `json:"created,omitempty"`
	Modified        *NotarizationTimestamp `json:"modified,omitempty"`
	Deleted         bool                   `json:"deleted,omitempty"`
}

type NotarizationTimestamp struct {
	Timestamp      int64  `json:"timestamp"`
	UserRecordName string `json:"userRecordName"`
	DeviceID       string `json:"deviceID"`
}

type TicketHeader struct {
	Magic        string
	MagicHex     string
	Version      uint32
	SignerLength uint32
}

type TicketInfo struct {
	SizeBytes    int
	Header       TicketHeader
	Certificates []*opb.Certificate
	CDHash       string
}

// parseS8chHeader parses the Apple notarization ticket header structure (s8ch format).
// The s8ch header is a 12-byte structure containing the magic bytes, version, and signer length.
//
// Header format:
//   - Bytes 0-3: Magic bytes "s8ch" (0x73 0x38 0x63 0x68)
//   - Bytes 4-7: Version (uint32, little-endian)
//   - Bytes 8-11: Signer data length (uint32, little-endian)
//
// References:
//   - Apple Code Signing Guide: https://developer.apple.com/documentation/security/notarizing_macos_software_before_distribution
//   - DER encoding: https://en.wikipedia.org/wiki/X.690#DER_encoding
func parseS8chHeader(data []byte) (TicketHeader, error) {
	if len(data) < 12 {
		return TicketHeader{}, fmt.Errorf("data too short for header")
	}

	magic := string(data[0:4])
	magicHex := fmt.Sprintf("%x", data[0:4])
	version := binary.LittleEndian.Uint32(data[4:8])
	signerLength := binary.LittleEndian.Uint32(data[8:12])

	return TicketHeader{
		Magic:        magic,
		MagicHex:     magicHex,
		Version:      version,
		SignerLength: signerLength,
	}, nil
}

// findCDHash extracts the Code Directory Hash (CDHash) from Apple notarization ticket data.
// The CDHash is a cryptographic hash that uniquely identifies the signed code.
// It searches for a specific byte pattern in the last 200 bytes of the ticket data.
//
// The CDHash is 20 bytes and follows the pattern: 0x00 0x00 0x00 0x00 0x02
//
// References:
//   - Code Directory format: https://github.com/apple-oss-distributions/Security/blob/main/OSX/libsecurity_codesigning/lib/CSCommon.h
//   - CDHash documentation: https://developer.apple.com/documentation/bundleresources/information_property_list/csresourcesfilepath
//
// Returns:
//   - Hex-encoded CDHash string if found
//   - Empty string if not found
func findCDHash(data []byte) string {
	searchStart := len(data) - 200
	if searchStart < 0 {
		searchStart = 0
	}
	tailData := data[searchStart:]

	pattern := []byte{0x00, 0x00, 0x00, 0x00, 0x02}
	pos := bytes.Index(tailData, pattern)

	if pos != -1 && pos+25 <= len(tailData) {
		cdhash := tailData[pos+5 : pos+25]
		return fmt.Sprintf("%x", cdhash)
	}

	return ""
}

// parseCertificateChain extracts X.509 certificates from Apple notarization ticket data.
// It scans the certificate chain data for DER-encoded X.509 certificates and parses them
// using Go's standard crypto/x509 library.
//
// DER (Distinguished Encoding Rules) format:
//   - Certificates start with tag 0x30 (SEQUENCE)
//   - Followed by 0x82 for long-form length encoding
//   - Next 2 bytes contain certificate length (big-endian)
//
// References:
//   - X.509 standard: https://www.itu.int/rec/T-REC-X.509
//   - DER encoding: https://en.wikipedia.org/wiki/X.690#DER_encoding
//   - Go crypto/x509: https://pkg.go.dev/crypto/x509
//
// Parameters:
//   - data: Full ticket data byte array
//   - offset: Starting position of certificate chain in data
//   - length: Length of certificate chain data
//
// Returns:
//   - Array of parsed Certificate protobuf objects
//   - Error if parsing fails
func parseCertificateChain(data []byte, offset int, length int) ([]*opb.Certificate, error) {
	var certificates []*opb.Certificate
	chainData := data[offset : offset+length]
	pos := 0

	for pos < len(chainData)-4 {
		cert, bytesRead := tryParseCertificateAt(chainData, pos)
		if cert != nil {
			certificates = append(certificates, cert)
		}
		pos += bytesRead
	}

	return certificates, nil
}

// tryParseCertificateAt attempts to parse a DER-encoded certificate at the given position.
// Returns the parsed certificate and the number of bytes to advance (1 if no cert found).
func tryParseCertificateAt(chainData []byte, pos int) (*opb.Certificate, int) {
	// Check for DER certificate start pattern (0x30 0x82)
	if !isDERCertificateStart(chainData, pos) {
		return nil, 1
	}

	if pos+4 > len(chainData) {
		return nil, 1
	}

	// Read certificate length (big-endian 16-bit)
	certLen := int(binary.BigEndian.Uint16(chainData[pos+2 : pos+4]))

	// Validate certificate length and bounds
	if certLen <= 100 || pos+certLen+4 > len(chainData) {
		return nil, 1
	}

	certBytes := chainData[pos : pos+certLen+4]
	cert, err := parseX509Certificate(certBytes)
	if err != nil || cert == nil {
		return nil, certLen + 4
	}

	return cert, certLen + 4
}

// isDERCertificateStart checks if the data at pos starts with DER certificate pattern (0x30 0x82).
func isDERCertificateStart(data []byte, pos int) bool {
	return pos+1 < len(data) && data[pos] == 0x30 && data[pos+1] == 0x82
}

// parseX509Certificate parses a DER-encoded X.509 certificate and converts it to protobuf format.
// Uses Go's standard crypto/x509 library to parse the certificate and extracts relevant fields
// including issuer, subject, validity dates, and Subject Alternative Names (SANs).
//
// The function performs the following:
//  1. Parses DER-encoded certificate data using x509.ParseCertificate
//  2. Extracts certificate metadata (serial number, validity dates, CA flag)
//  3. Extracts issuer and subject information (CN, Organization, Country)
//  4. Validates certificate expiration status
//  5. Extracts Subject Alternative Names (DNS names and IP addresses)
//
// References:
//   - X.509 certificate format: https://datatracker.ietf.org/doc/html/rfc5280
//   - Go crypto/x509: https://pkg.go.dev/crypto/x509
//   - Subject Alternative Names: https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.6
//
// Parameters:
//   - certData: DER-encoded X.509 certificate bytes
//
// Returns:
//   - Parsed Certificate protobuf object with all fields populated
//   - Error if parsing fails
func parseX509Certificate(certData []byte) (*opb.Certificate, error) {
	cert, err := x509.ParseCertificate(certData)
	if err != nil {
		return nil, fmt.Errorf("failed to parse X.509 certificate: %v", err)
	}

	pbCert := &opb.Certificate{
		SerialNumber: cert.SerialNumber.String(),
		ValidFrom:    cert.NotBefore.UTC().Format("2006-01-02 15:04:05 UTC"),
		ValidTo:      cert.NotAfter.UTC().Format("2006-01-02 15:04:05 UTC"),
		IsValidCert:  true,
		IsCa:         cert.IsCA,
	}

	// Set up issuer/subject information
	if cert.Subject.CommonName != "" || len(cert.Subject.Organization) > 0 {
		pbCert.Issuer = &opb.CertIssuerSubj{
			SubjectName:    cert.Subject.CommonName,
			SubjectOrg:     strings.Join(cert.Subject.Organization, ", "),
			SubjectOrgUnit: strings.Join(cert.Subject.OrganizationalUnit, ", "),
		}
	}

	if cert.Issuer.CommonName != "" || len(cert.Issuer.Organization) > 0 {
		if pbCert.Issuer == nil {
			pbCert.Issuer = &opb.CertIssuerSubj{}
		}
		pbCert.Issuer.IssuerName = cert.Issuer.CommonName
		pbCert.Issuer.IssuerOrg = strings.Join(cert.Issuer.Organization, ", ")
		pbCert.Issuer.IssuerCountry = strings.Join(cert.Issuer.Country, ", ")
	}

	// Check if certificate is expired
	now := time.Now()
	if now.After(cert.NotAfter) {
		pbCert.IsValidCert = false
	}

	// Set email addresses and SANs if present
	if len(cert.EmailAddresses) > 0 {
		pbCert.Emails = cert.EmailAddresses
	}

	// Extract SANs (Subject Alternative Names)
	var sans []string
	for _, name := range cert.DNSNames {
		sans = append(sans, name)
	}
	for _, ip := range cert.IPAddresses {
		sans = append(sans, ip.String())
	}
	if len(sans) > 0 {
		pbCert.Sans = sans
	}

	return pbCert, nil
}

// parseNotarizationTicket parses an Apple notarization ticket and extracts certificate chain and CDHash.
// The ticket is a base64-encoded binary structure containing a header, certificate chain, and signature data.
//
// Ticket structure:
//   - Bytes 0-11: s8ch header (magic, version, signer length)
//   - Bytes 12+: DER-encoded certificate chain
//   - Tail bytes: CDHash and signature data
//
// The function performs the following:
//  1. Decodes base64 ticket data
//  2. Parses s8ch header to get certificate chain length
//  3. Extracts and parses X.509 certificate chain
//  4. Assigns certificate roles (leaf, intermediate, root) based on position
//  5. Extracts CDHash from ticket tail
//
// References:
//   - Apple Notarization: https://developer.apple.com/documentation/security/notarizing_macos_software_before_distribution
//   - Code Signing: https://developer.apple.com/library/archive/technotes/tn2206/_index.html
//
// Parameters:
//   - ticketBase64: Base64-encoded notarization ticket string
//
// Returns:
//   - TicketInfo containing parsed header, certificates, and CDHash
//   - Error if parsing fails
func parseNotarizationTicket(ticketBase64 string) (*TicketInfo, error) {
	ticketData, err := base64.StdEncoding.DecodeString(ticketBase64)
	if err != nil {
		return nil, fmt.Errorf("failed to decode base64 ticket: %v", err)
	}

	if len(ticketData) < 12 {
		return nil, fmt.Errorf("ticket data too short")
	}

	header, err := parseS8chHeader(ticketData[0:12])
	if err != nil {
		return nil, fmt.Errorf("failed to parse header: %v", err)
	}

	certOffset := 12
	certLength := int(header.SignerLength)

	if certOffset+certLength > len(ticketData) {
		return nil, fmt.Errorf("certificate data extends beyond ticket")
	}

	certificates, err := parseCertificateChain(ticketData, certOffset, certLength)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate chain: %v", err)
	}

	// Set certificate chain positions and roles
	for i, cert := range certificates {
		cert.ChainPosition = int32(i)
		if i == 0 {
			cert.IsLeaf = true
		} else if i == len(certificates)-1 {
			cert.IsRoot = true
		} else {
			cert.IsIntermediate = true
		}
	}

	cdhash := findCDHash(ticketData)

	return &TicketInfo{
		SizeBytes:    len(ticketData),
		Header:       header,
		Certificates: certificates,
		CDHash:       cdhash,
	}, nil
}

// checkNotarization queries Apple's CloudKit API to verify binary notarization status.
// Uses the Apple ticket delivery service to check if a binary with the given CDHash has been notarized.
//
// The function performs the following:
//  1. Creates a CloudKit API request with record name "2/2/{cdHash}"
//  2. Sends POST request to Apple's ticket delivery service
//  3. Parses the response to determine notarization status
//  4. Extracts signed ticket data and parses certificates if notarized
//  5. Extracts timestamp information
//
// API Response handling:
//   - NOT_FOUND: Binary is not notarized (not an error)
//   - Server error: Returns error in NotarizationInfo
//   - Success: Parses ticket and extracts certificates
//
// References:
//   - Apple CloudKit API: https://developer.apple.com/documentation/cloudkit
//   - Notarization workflow: https://developer.apple.com/documentation/security/notarizing_macos_software_before_distribution
//   - Ticket delivery service: https://api.apple-cloudkit.com/database/1/com.apple.gk.ticket-delivery/production/public/records/lookup
//
// Parameters:
//   - cdHash: Code Directory Hash (hex-encoded SHA-1 or SHA-256)
//
// Returns:
//   - NotarizationInfo containing status, timestamp, certificates, and any errors
func checkNotarization(cdHash string) *opb.NotarizationInfo {
	notarization := &opb.NotarizationInfo{
		IsNotarized: false,
		Error:       "",
		RecordName:  fmt.Sprintf("2/2/%s", cdHash),
	}

	record, err := fetchNotarizationRecord(notarization.RecordName)
	if err != nil {
		notarization.Error = err.Error()
		return notarization
	}

	// Handle NOT_FOUND - binary is not notarized (not an error condition)
	if record.ServerErrorCode == "NOT_FOUND" || record.Reason == "Record not found" {
		return notarization
	}

	// Handle server errors
	if record.ServerErrorCode != "" {
		notarization.Error = fmt.Sprintf("Server error: %s - %s", record.ServerErrorCode, record.Reason)
		return notarization
	}

	// Parse successful notarization record
	populateNotarizationInfo(notarization, record)
	return notarization
}

// fetchNotarizationRecord makes an HTTP request to Apple's CloudKit API to fetch notarization record.
func fetchNotarizationRecord(recordName string) (*NotarizationRecord, error) {
	requestPayload := NotarizationRequest{
		Records: map[string]interface{}{
			"recordName": recordName,
		},
	}

	jsonData, err := json.Marshal(requestPayload)
	if err != nil {
		return nil, fmt.Errorf("Failed to marshal request: %v", err)
	}

	req, err := http.NewRequest("POST", appleNotarizationAPI, bytes.NewBuffer(jsonData))
	if err != nil {
		return nil, fmt.Errorf("Failed to create request: %v", err)
	}

	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{
		Timeout: 10 * time.Second,
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("HTTP request failed: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("Failed to read response: %v", err)
	}

	var apiResponse NotarizationResponse
	if err := json.Unmarshal(body, &apiResponse); err != nil {
		return nil, fmt.Errorf("Failed to parse response: %v", err)
	}

	if len(apiResponse.Records) == 0 {
		return nil, fmt.Errorf("No records in response")
	}

	return &apiResponse.Records[0], nil
}

// populateNotarizationInfo populates NotarizationInfo from a successful API record response.
func populateNotarizationInfo(notarization *opb.NotarizationInfo, record *NotarizationRecord) {
	if record.Fields == nil {
		return
	}

	notarization.IsNotarized = true
	notarization.Deleted = record.Deleted

	// Extract and parse signed ticket
	extractSignedTicket(notarization, record.Fields)

	// Extract timestamp information
	if record.Created != nil {
		notarization.Timestamp = record.Created.Timestamp
		timestamp := time.Unix(0, record.Created.Timestamp*int64(time.Millisecond))
		notarization.TimestampUtc = timestamp.UTC().Format(time.RFC3339)
	}
}

// extractSignedTicket extracts the signed ticket from record fields and parses certificates.
func extractSignedTicket(notarization *opb.NotarizationInfo, fields map[string]interface{}) {
	signedTicketField, exists := fields["signedTicket"]
	if !exists {
		return
	}

	ticketMap, ok := signedTicketField.(map[string]interface{})
	if !ok {
		return
	}

	ticketValue, exists := ticketMap["value"]
	if !exists {
		return
	}

	ticketStr, ok := ticketValue.(string)
	if !ok {
		return
	}

	notarization.SignedTicket = ticketStr

	// Parse the ticket to extract certificates
	ticketInfo, err := parseNotarizationTicket(ticketStr)
	if err != nil {
		return
	}

	notarization.Certificates = ticketInfo.Certificates
	if ticketInfo.CDHash != "" {
		notarization.ExtractedCdhash = ticketInfo.CDHash
	}
}

// checkNotarizationForCDHash validates CDHash input and checks notarization status.
// This is the main entry point for notarization verification.
//
// The CDHash (Code Directory Hash) is a cryptographic hash that uniquely identifies
// a signed binary. It can be either SHA-1 (20 bytes) or SHA-256 (32 bytes).
//
// References:
//   - Code Directory: https://developer.apple.com/documentation/bundleresources/information_property_list
//   - CDHash format: https://developer.apple.com/library/archive/technotes/tn2206/_index.html
//
// Parameters:
//   - cdHash: Hex-encoded Code Directory Hash (must not be empty)
//
// Returns:
//   - NotarizationInfo with error if CDHash is empty
//   - NotarizationInfo with API query results otherwise
func checkNotarizationForCDHash(cdHash string) *opb.NotarizationInfo {
	if cdHash == "" {
		return &opb.NotarizationInfo{
			IsNotarized: false,
			Error:       "CDHash is empty",
			RecordName:  "",
			Deleted:     false,
		}
	}

	return checkNotarization(cdHash)
}