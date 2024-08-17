package logic

import (
	"errors"
	"fmt"
	"github.com/graphql-iam/agent/src/config"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"io"
	"net/http"
	"os"
)

type JwtParser struct {
	Cfg    config.Config
	KeySet *jwk.Set
}

func (k *JwtParser) Parse(authHeader string) (jwt.Token, error) {
	tokenString := authHeader[len("Bearer "):]

	if k.KeySet != nil {
		return jwt.Parse([]byte(tokenString), jwt.WithKeySet(*k.KeySet))
	}

	alg := jwa.KeyAlgorithmFrom(k.Cfg.Auth.JwtOptions.SigningMethod)

	if _, invalid := alg.(jwa.InvalidKeyAlgorithm); invalid {
		return nil, fmt.Errorf("%s is not a valid key algorithm", k.Cfg.Auth.JwtOptions.SigningMethod)
	}

	key, err := k.resolveKey()

	if err != nil {
		return nil, errors.New(err.Error())
	}

	return jwt.Parse([]byte(tokenString), jwt.WithKey(alg, key))
}

func (k *JwtParser) resolveKey() (jwk.Key, error) {
	keyBytes, err := k.resolveBytes()
	if err != nil {
		return nil, err
	}
	return jwk.ParseKey(keyBytes)
}

func (k *JwtParser) resolveBytes() ([]byte, error) {
	if k.Cfg.Auth.JwtOptions.KeyUrl != "" {
		return loadKeyFromUrl(k.Cfg.Auth.JwtOptions.KeyUrl)
	} else if k.Cfg.Auth.JwtOptions.KeyPath != "" {
		return loadKeyFromFile(k.Cfg.Auth.JwtOptions.KeyPath)
	} else if k.Cfg.Auth.JwtOptions.Key != "" {
		return []byte(k.Cfg.Auth.JwtOptions.Key), nil
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
