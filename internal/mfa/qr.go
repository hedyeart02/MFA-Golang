package mfa

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"image/png"
	"net/url"

	"github.com/boombuler/barcode"
	"github.com/boombuler/barcode/qr"
)

// BuildProvisioningURI constructs a standard RFC 6238 authenticator provisioning URI.
func BuildProvisioningURI(issuer, accountName, secret string) string {
	if issuer == "" {
		issuer = "SAMLGuard"
	}
	label := fmt.Sprintf("%s:%s", issuer, accountName)
	v := url.Values{}
	v.Set("secret", secret)
	v.Set("issuer", issuer)
	v.Set("algorithm", "SHA1")
	v.Set("digits", "6")
	v.Set("period", "30")

	u := url.URL{
		Scheme:   "otpauth",
		Host:     "totp",
		Path:     label,
		RawQuery: v.Encode(),
	}
	return u.String()
}

// GenerateQRCodePNGDataURI generates a PNG QR code for the given URI and formats it as an inline Data URI.
func GenerateQRCodePNGDataURI(content string, size int) (string, error) {
	if size <= 0 {
		size = 200
	}

	qrCode, err := qr.Encode(content, qr.M, qr.Auto)
	if err != nil {
		return "", fmt.Errorf("encoding qr code: %w", err)
	}

	scaled, err := barcode.Scale(qrCode, size, size)
	if err != nil {
		return "", fmt.Errorf("scaling qr code: %w", err)
	}

	var buf bytes.Buffer
	if err := png.Encode(&buf, scaled); err != nil {
		return "", fmt.Errorf("png encoding qr code: %w", err)
	}

	b64 := base64.StdEncoding.EncodeToString(buf.Bytes())
	return "data:image/png;base64," + b64, nil
}
