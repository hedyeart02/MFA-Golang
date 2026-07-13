package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"
)

func main() {
	certDir := "./cert"
	if err := os.MkdirAll(certDir, 0755); err != nil {
		fmt.Printf("failed to create cert directory: %v\n", err)
		return
	}

	fmt.Println("=== Go SAMLGuard Certificate Generator ===")

	// 1. Generate SAML signing certificate
	fmt.Println("[1/4] Generating SAML signing certificate...")
	if err := generateSelfSignedCert(
		filepath.Join(certDir, "saml-signing.key"),
		filepath.Join(certDir, "saml-signing.crt"),
		"SAMLGuard Signing",
		[]string{"samlguard.example.com"},
		nil,
	); err != nil {
		fmt.Printf("failed to generate SAML signing cert: %v\n", err)
		return
	}

	// 2. Generating TLS server certificate
	fmt.Println("[2/4] Generating TLS server certificate...")
	if err := generateSelfSignedCert(
		filepath.Join(certDir, "server.key"),
		filepath.Join(certDir, "server.crt"),
		"samlguard.example.com",
		[]string{"samlguard.example.com", "localhost"},
		[]net.IP{net.ParseIP("127.0.0.1")},
	); err != nil {
		fmt.Printf("failed to generate TLS server cert: %v\n", err)
		return
	}

	// 3. Generating JWT signing keys
	fmt.Println("[3/4] Generating JWT signing keys...")
	if err := generateJWTKeys(
		filepath.Join(certDir, "jwt-private.pem"),
		filepath.Join(certDir, "jwt-public.pem"),
	); err != nil {
		fmt.Printf("failed to generate JWT keys: %v\n", err)
		return
	}

	// 4. Generating MFA encryption key
	fmt.Println("[4/4] Generating MFA encryption key...")
	mfaKeyBytes := make([]byte, 32)
	if _, err := rand.Read(mfaKeyBytes); err != nil {
		fmt.Printf("failed to generate MFA encryption key: %v\n", err)
		return
	}
	mfaKeyHex := hex.EncodeToString(mfaKeyBytes)
	if err := os.WriteFile(filepath.Join(certDir, "mfa-encryption.key"), []byte(mfaKeyHex), 0600); err != nil {
		fmt.Printf("failed to write MFA encryption key: %v\n", err)
		return
	}

	fmt.Printf("\n=== Certificates generated successfully ===\n")
	fmt.Printf("MFA Encryption Key: %s\n", mfaKeyHex)
}

func generateSelfSignedCert(keyPath, certPath, commonName string, dnsNames []string, ipAddresses []net.IP) error {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return err
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   commonName,
			Organization: []string{"SAMLGuard"},
			Country:      []string{"US"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(1, 0, 0), // 1 year
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              dnsNames,
		IPAddresses:           ipAddresses,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return err
	}

	certOut, err := os.Create(certPath)
	if err != nil {
		return err
	}
	defer certOut.Close()
	if err := pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes}); err != nil {
		return err
	}

	keyOut, err := os.OpenFile(keyPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	defer keyOut.Close()
	privBytes := x509.MarshalPKCS1PrivateKey(priv)
	if err := pem.Encode(keyOut, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: privBytes}); err != nil {
		return err
	}

	return nil
}

func generateJWTKeys(privatePath, publicPath string) error {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}

	// Write private key
	privOut, err := os.OpenFile(privatePath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	defer privOut.Close()
	privBytes := x509.MarshalPKCS1PrivateKey(priv)
	if err := pem.Encode(privOut, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: privBytes}); err != nil {
		return err
	}

	// Write public key
	pubOut, err := os.Create(publicPath)
	if err != nil {
		return err
	}
	defer pubOut.Close()
	pubBytes, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		return err
	}
	if err := pem.Encode(pubOut, &pem.Block{Type: "PUBLIC KEY", Bytes: pubBytes}); err != nil {
		return err
	}

	return nil
}
