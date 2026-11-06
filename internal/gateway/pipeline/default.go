package pipeline

import (
	"context"
	"errors"
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
	BindingResolver    binding.BindingResolver
	Decoder            binding.RequestDecoder
	Parser             parser.Parser
	Normalizer         builder.Normalizer
	SyntaxValidator    validator.SyntaxValidator
	SignatureValidator validator.SignatureValidator
	SchemaValidator    validator.SchemaValidator
	ReplayValidator    validator.ReplayValidator
	ClockValidator     validator.ClockValidator
	PolicyValidator    validator.PolicyValidator
	MetadataResolver   resolver.MetadataResolver
	ProviderResolver   resolver.ProviderResolver
	ContextBuilder     builder.ContextBuilder
}

// Validate checks that all mandatory pipeline dependencies are injected
func (p *DefaultAuthnPipeline) Validate() error {
	if p == nil {
		return errors.New("pipeline cannot be nil")
	}
	if p.BindingResolver == nil {
		return errors.New("pipeline: BindingResolver is mandatory")
	}
	if p.Decoder == nil {
		return errors.New("pipeline: Decoder is mandatory")
	}
	if p.Parser == nil {
		return errors.New("pipeline: Parser is mandatory")
	}
	if p.Normalizer == nil {
		return errors.New("pipeline: Normalizer is mandatory")
	}
	if p.SyntaxValidator == nil {
		return errors.New("pipeline: SyntaxValidator is mandatory")
	}
	if p.SignatureValidator == nil {
		return errors.New("pipeline: SignatureValidator is mandatory")
	}
	if p.SchemaValidator == nil {
		return errors.New("pipeline: SchemaValidator is mandatory")
	}
	if p.ReplayValidator == nil {
		return errors.New("pipeline: ReplayValidator is mandatory")
	}
	if p.ClockValidator == nil {
		return errors.New("pipeline: ClockValidator is mandatory")
	}
	if p.PolicyValidator == nil {
		return errors.New("pipeline: PolicyValidator is mandatory")
	}
	if p.MetadataResolver == nil {
		return errors.New("pipeline: MetadataResolver is mandatory")
	}
	if p.ProviderResolver == nil {
		return errors.New("pipeline: ProviderResolver is mandatory")
	}
	if p.ContextBuilder == nil {
		return errors.New("pipeline: ContextBuilder is mandatory")
	}
	return nil
}

func (p *DefaultAuthnPipeline) Execute(ctx context.Context, input interface{}) (*model.AuthenticationContext, error) {
	if p == nil {
		return nil, errors.New("pipeline cannot be nil")
	}

	req, ok := input.(*http.Request)
	if !ok || req == nil {
		return nil, fmt.Errorf("invalid input type, expected non-nil *http.Request")
	}

	// 1. Binding Resolution
	if p.BindingResolver == nil {
		return nil, errors.New("pipeline: BindingResolver dependency is missing")
	}
	bindingType, err := p.BindingResolver.Resolve(req)
	if err != nil {
		return nil, err
	}

	// 2. Decoder
	if p.Decoder == nil {
		return nil, errors.New("pipeline: Decoder dependency is missing")
	}
	transportRes, err := p.Decoder.Decode(req, bindingType)
	if err != nil {
		return nil, err
	}

	authCtx := &model.AuthenticationContext{
		RequestID:        req.Header.Get("X-Request-Id"),
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
		if err != nil {
			return nil, err
		}
		authCtx.Metadata = meta
	}

	// 6. Provider Resolution
	if p.ProviderResolver != nil {
		provider, err := p.ProviderResolver.ResolveProvider(authCtx)
		if err != nil {
			return nil, err
		}
		authCtx.ProviderType = provider
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
