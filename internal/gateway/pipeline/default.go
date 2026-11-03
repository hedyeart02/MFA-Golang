package pipeline

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/hidayat-SE/samlguard/internal/gateway/binding"
	"github.com/hidayat-SE/samlguard/internal/gateway/builder"
	"github.com/hidayat-SE/samlguard/internal/gateway/model"
	"github.com/hidayat-SE/samlguard/internal/gateway/parser"
	"github.com/hidayat-SE/samlguard/internal/gateway/resolver"
	"github.com/hidayat-SE/samlguard/internal/gateway/validator"
)

type DefaultAuthnPipeline struct {
	BindingResolver  binding.BindingResolver
	Decoder          binding.RequestDecoder
	Parser           parser.Parser
	Normalizer       builder.Normalizer
	SyntaxValidator  validator.SyntaxValidator
	SignatureValidator validator.SignatureValidator
	SchemaValidator    validator.SchemaValidator
	ReplayValidator    validator.ReplayValidator
	ClockValidator     validator.ClockValidator
	PolicyValidator  validator.PolicyValidator
	MetadataResolver resolver.MetadataResolver
	ProviderResolver resolver.ProviderResolver
	ContextBuilder   builder.ContextBuilder
}

func (p *DefaultAuthnPipeline) Execute(ctx context.Context, input interface{}) (*model.AuthenticationContext, error) {
	req, ok := input.(*http.Request)
	if !ok {
		return nil, fmt.Errorf("invalid input type, expected *http.Request")
	}

	// 1. Binding Resolution
	bindingType, err := p.BindingResolver.Resolve(req)
	if err != nil {
		return nil, err
	}

	// 2. Decoder
	transportRes, err := p.Decoder.Decode(req, bindingType)
	if err != nil {
		return nil, err
	}

	authCtx := &model.AuthenticationContext{
		RequestID:        req.Header.Get("X-Request-Id"), // Setup placeholder context
		OriginalClientIP: req.RemoteAddr,
		RawXML:           transportRes.InflatedBytes,
		RawRequest:       transportRes.CompressedBytes,
		RawBinding:       bindingType,
		RelayState:       transportRes.RelayState,
		ReceivedAt:       time.Now(),
	}

	// 3. Parser & Normalizer
	if p.Parser != nil {
		parseRes, err := p.Parser.ParseAuthnRequest(authCtx.RawXML)
		if err != nil {
			return nil, err
		}
		if p.Normalizer != nil {
			if err := p.Normalizer.Normalize(parseRes, authCtx); err != nil {
				return nil, err
			}
		}
	}
	authCtx.ReceivedAt = time.Now()

	// 4. Validation
	if p.SyntaxValidator != nil {
		if err := p.SyntaxValidator.ValidateSyntax(authCtx); err != nil {
			return nil, err
		}
	}
	if p.SchemaValidator != nil {
		if err := p.SchemaValidator.ValidateSchema(authCtx); err != nil {
			return nil, err
		}
	}
	if p.SignatureValidator != nil {
		if err := p.SignatureValidator.ValidateSignature(authCtx); err != nil {
			return nil, err
		}
	}
	if p.ReplayValidator != nil {
		if err := p.ReplayValidator.ValidateReplay(authCtx); err != nil {
			return nil, err
		}
	}
	if p.ClockValidator != nil {
		if err := p.ClockValidator.ValidateClockSkew(authCtx); err != nil {
			return nil, err
		}
	}
	if p.PolicyValidator != nil {
		if err := p.PolicyValidator.ValidatePolicy(authCtx); err != nil {
			return nil, err
		}
	}

	// 5. Metadata Resolution
	if p.MetadataResolver != nil {
		meta, err := p.MetadataResolver.Resolve(ctx, authCtx.Issuer)
		if err == nil {
			authCtx.Metadata = meta
		}
	}

	// 6. Provider Resolution
	if p.ProviderResolver != nil {
		provider, err := p.ProviderResolver.ResolveProvider(authCtx)
		if err == nil {
			authCtx.ProviderType = provider
		}
	}

	// 7. Context Builder
	if p.ContextBuilder != nil {
		authCtx, err = p.ContextBuilder.Build(authCtx)
		if err != nil {
			return nil, err
		}
	}

	return authCtx, nil
}
