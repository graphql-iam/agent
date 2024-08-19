package service

import (
	"context"
	"errors"
	"fmt"
	"github.com/graphql-iam/agent/src/config"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"io"
	"net/http"
	"os"
	"time"
)

type JwtService struct {
	cfg    config.Config
	keySet *jwk.Set
}

func NewJwtService(cfg config.Config) *JwtService {
	return &JwtService{
		cfg:    cfg,
		keySet: getCachedJWKS(cfg),
	}
}

func getCachedJWKS(cfg config.Config) *jwk.Set {
	if cfg.Auth.JwtOptions.JwksUrl == "" {
		return nil
	}

	jwkCache := jwk.NewCache(context.Background())

	// register a minimum refresh interval for this URL.
	// when not specified, defaults to cache-Control and similar resp headers
	err := jwkCache.Register(cfg.Auth.JwtOptions.JwksUrl, jwk.WithMinRefreshInterval(10*time.Minute))
	if err != nil {
		panic("failed to register jwk location")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// fetch once on application startup
	_, err = jwkCache.Refresh(ctx, cfg.Auth.JwtOptions.JwksUrl)
	if err != nil {
		panic("failed to fetch on startup")
	}
	// create the cached key set
	cachedSet := jwk.NewCachedSet(jwkCache, cfg.Auth.JwtOptions.JwksUrl)

	return &cachedSet
}

func (j *JwtService) Parse(authHeader string) (jwt.Token, error) {
	tokenString := authHeader[len("Bearer "):]

	if j.keySet != nil {
		return jwt.Parse([]byte(tokenString), jwt.WithKeySet(*j.keySet))
	}

	alg := jwa.KeyAlgorithmFrom(j.cfg.Auth.JwtOptions.SigningMethod)

	if _, invalid := alg.(jwa.InvalidKeyAlgorithm); invalid {
		return nil, fmt.Errorf("%s is not a valid key algorithm", j.cfg.Auth.JwtOptions.SigningMethod)
	}

	key, err := j.resolveKey()

	if err != nil {
		return nil, errors.New(err.Error())
	}

	return jwt.Parse([]byte(tokenString), jwt.WithKey(alg, key))
}

func (j *JwtService) resolveKey() (jwk.Key, error) {
	keyBytes, err := j.resolveBytes()
	if err != nil {
		return nil, err
	}
	return jwk.ParseKey(keyBytes)
}

func (j *JwtService) resolveBytes() ([]byte, error) {
	if j.cfg.Auth.JwtOptions.KeyUrl != "" {
		return loadKeyFromUrl(j.cfg.Auth.JwtOptions.KeyUrl)
	} else if j.cfg.Auth.JwtOptions.KeyPath != "" {
		return loadKeyFromFile(j.cfg.Auth.JwtOptions.KeyPath)
	} else if j.cfg.Auth.JwtOptions.Key != "" {
		return []byte(j.cfg.Auth.JwtOptions.Key), nil
	} else {
		return nil, errors.New("could not resolve JWT signing key")
	}
}

func loadKeyFromFile(path string) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return []byte{}, err
	}
	defer file.Close()

	return io.ReadAll(file)
}

func loadKeyFromUrl(url string) ([]byte, error) {
	res, err := http.Get(url)
	if err != nil {
		return nil, err
	}

	return io.ReadAll(res.Body)
}
