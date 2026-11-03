package metadata

import (
	"errors"
	"strings"

	"github.com/hidayat-SE/samlguard/internal/federation/model"
)

// Normalizer takes the parsed struct and enriches/normalizes endpoints and certificates
type Normalizer struct{}

func (n *Normalizer) Normalize(rawXML []byte, md *model.MetadataDescriptor) error {
	if md == nil {
		return errors.New("metadata descriptor cannot be nil")
	}

	// If md was unpopulated (e.g. minimal descriptor), parse and populate it
	if len(md.SSOEndpoints) == 0 && len(md.Certificates) == 0 && len(rawXML) > 0 {
		p := &Parser{}
		parsed, err := p.Parse(rawXML)
		if err != nil {
			return err
		}
		*md = *parsed
	}

	// Normalize Endpoints: trim spaces and ensure consistency
	for i := range md.SSOEndpoints {
		md.SSOEndpoints[i].Binding = strings.TrimSpace(md.SSOEndpoints[i].Binding)
		md.SSOEndpoints[i].Location = strings.TrimSpace(md.SSOEndpoints[i].Location)
		md.SSOEndpoints[i].Response = strings.TrimSpace(md.SSOEndpoints[i].Response)
	}
	for i := range md.SLOEndpoints {
		md.SLOEndpoints[i].Binding = strings.TrimSpace(md.SLOEndpoints[i].Binding)
		md.SLOEndpoints[i].Location = strings.TrimSpace(md.SLOEndpoints[i].Location)
		md.SLOEndpoints[i].Response = strings.TrimSpace(md.SLOEndpoints[i].Response)
	}

	return nil
}
