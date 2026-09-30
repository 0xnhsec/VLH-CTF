// VLH-CTF — ASLV M4 aslv-api: deliberately loose JWT validation.
//
// This file IS the M5→M4 trust edge (arch §5.2): M4 validates ONLY the
// signature — RS256 against the JWKS at JWKS_URL (M5 in full mode,
// stub-auth standalone) or HS256 where the HMAC key is the JWK's public
// `n` + `e` strings glued with a dot (classic algorithm confusion). sub/role
// claims are accepted WITHOUT aud/scope/owner checks, by design.
package main

import (
        "crypto"
        "crypto/hmac"
        "crypto/rsa"
        "crypto/sha256"
        "encoding/base64"
        "encoding/json"
        "fmt"
        "io"
        "math/big"
        "net/http"
        "strings"
        "sync"
        "time"
)

/* --------------------------------------------------------------- JWKS cache */

type jwk struct {
        Kty string `json:"kty"`
        Kid string `json:"kid"`
        N   string `json:"n"`
        E   string `json:"e"`
        Alg string `json:"alg"`
        Use string `json:"use"`
}

var (
        jwksMu      sync.Mutex
        jwksKeys    []jwk
        jwksFetched time.Time
        jwksClient  = &http.Client{Timeout: 5 * time.Second}
)

// jwksInit warms the cache in the background; a missing JWKS must never
// block boot (standalone m4 may start before stub-auth).
func jwksInit() {
        go func() { _, _ = fetchJWKS() }()
}

func fetchJWKS() ([]jwk, error) {
        jwksMu.Lock()
        defer jwksMu.Unlock()
        if len(jwksKeys) > 0 && time.Since(jwksFetched) < 5*time.Minute {
                return jwksKeys, nil
        }
        resp, err := jwksClient.Get(cfg.jwksURL)
        if err != nil {
                return nil, fmt.Errorf("jwks fetch failed: %w", err)
        }
        defer resp.Body.Close()
        if resp.StatusCode != http.StatusOK {
                return nil, fmt.Errorf("jwks fetch -> %s", resp.Status)
        }
        var out struct {
                Keys []jwk `json:"keys"`
        }
        if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&out); err != nil {
                return nil, fmt.Errorf("jwks parse failed: %w", err)
        }
        rsa := []jwk{}
        for _, k := range out.Keys {
                if k.Kty == "RSA" && k.N != "" && k.E != "" {
                        rsa = append(rsa, k)
                }
        }
        if len(rsa) == 0 {
                return nil, fmt.Errorf("jwks contains no usable RSA keys")
        }
        jwksKeys = rsa
        jwksFetched = time.Now()
        return rsa, nil
}

func pickKey(keys []jwk, kid string) jwk {
        if kid != "" {
                for _, k := range keys {
                        if k.Kid == kid {
                                return k
                        }
                }
        }
        return keys[0]
}

/* ------------------------------------------------------- signature checkers */

func rsaPublicKey(n64, e64 string) (*rsa.PublicKey, error) {
        nb, err := base64.RawURLEncoding.DecodeString(n64)
        if err != nil {
                return nil, fmt.Errorf("bad JWK n: %w", err)
        }
        eb, err := base64.RawURLEncoding.DecodeString(e64)
        if err != nil {
                return nil, fmt.Errorf("bad JWK e: %w", err)
        }
        pub := &rsa.PublicKey{N: new(big.Int).SetBytes(nb)}
        e := new(big.Int).SetBytes(eb)
        if !e.IsInt64() || e.Int64() <= 0 || e.Int64() > 1<<31 {
                return nil, fmt.Errorf("bad JWK exponent")
        }
        pub.E = int(e.Int64())
        return pub, nil
}

func verifyRS256(signingInput string, sig []byte, key jwk) error {
        pub, err := rsaPublicKey(key.N, key.E)
        if err != nil {
                return err
        }
        digest := sha256.Sum256([]byte(signingInput))
        return rsa.VerifyPKCS1v15(pub, crypto.SHA256, digest[:], sig)
}

// verifyHS256Confusion: HS256 tokens are verified with the RSA public key
// MATERIAL (the base64url `n` and `e` strings, joined with a dot) as the HMAC
// secret — the algorithm-confusion feeder for the identity-led chain.
func verifyHS256Confusion(signingInput string, sig []byte, key jwk) bool {
        secret := key.N + "." + key.E
        mac := hmac.New(sha256.New, []byte(secret))
        mac.Write([]byte(signingInput))
        return hmac.Equal(mac.Sum(nil), sig)
}

/* ------------------------------------------------------------ token verify */

func verifyJWT(token string) (map[string]any, error) {
        parts := strings.Split(token, ".")
        if len(parts) != 3 {
                return nil, fmt.Errorf("malformed token")
        }
        headerRaw, err := base64.RawURLEncoding.DecodeString(parts[0])
        if err != nil {
                return nil, fmt.Errorf("bad header encoding")
        }
        var header map[string]any
        if err := json.Unmarshal(headerRaw, &header); err != nil {
                return nil, fmt.Errorf("bad header JSON")
        }
        claimsRaw, err := base64.RawURLEncoding.DecodeString(parts[1])
        if err != nil {
                return nil, fmt.Errorf("bad claims encoding")
        }
        var claims map[string]any
        if err := json.Unmarshal(claimsRaw, &claims); err != nil {
                return nil, fmt.Errorf("bad claims JSON")
        }
        sig, err := base64.RawURLEncoding.DecodeString(parts[2])
        if err != nil {
                return nil, fmt.Errorf("bad signature encoding")
        }
        alg, _ := header["alg"].(string)
        kid, _ := header["kid"].(string)
        signingInput := parts[0] + "." + parts[1]

        keys, err := fetchJWKS()
        if err != nil {
                return nil, err
        }
        key := pickKey(keys, kid)

        switch alg {
        case "RS256":
                if err := verifyRS256(signingInput, sig, key); err != nil {
                        return nil, fmt.Errorf("rs256 signature mismatch")
                }
        case "HS256":
                if !verifyHS256Confusion(signingInput, sig, key) {
                        return nil, fmt.Errorf("hs256 signature mismatch")
                }
        default:
                return nil, fmt.Errorf("unsupported alg %q", alg)
        }
        return claims, nil
}
