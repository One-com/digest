// Packlage digest provides a wrapper for http.Client that supports HTTP Digest
// auth for GET and POST (and other) HTTP methods
package digest

import (
	"crypto/md5"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/http"
	"strings"
)

// Type AuthClient is a wrapper around http.Client
type AuthClient struct {
	*http.Client
	User     string
	Password string
}

// NewAuthClient returns a new AuthClient instance
func NewAuthClient(c *http.Client, user, pass string) *AuthClient {

	return &AuthClient{Client: c, User: user, Password: pass}

}

//Do performs a request, and performs digeset authentication
func (c *AuthClient) Do(r *http.Request) (*http.Response, error) {

	initreq, err := http.NewRequest(r.Method, r.URL.String(), nil)
	if err != nil {
		return nil, err
	}

	// Copy headers
	(*initreq).Header = (*r).Header

	resp, err := c.Do(initreq)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusUnauthorized {
		// No auth necessary
		// redo the request with the body if needed
		if r.Method != "GET" {
			resp, err = c.Do(r)
		}
	} else {

		digestParts := digestParts(resp)
		digestParts["uri"] = r.URL.Path
		digestParts["method"] = r.Method
		digestParts["username"] = c.User
		digestParts["password"] = c.Password
		r.Header.Set("Authorization", getDigestAuthrization(digestParts))

		resp, err = c.Do(r)
	}

	return resp, err
}

func digestParts(resp *http.Response) map[string]string {
	result := map[string]string{}
	if len(resp.Header["Www-Authenticate"]) > 0 {
		wantedHeaders := []string{"nonce", "realm", "qop", "algorithm", "opaque"}
		responseHeaders := strings.Split(resp.Header["Www-Authenticate"][0], ",")
		for _, r := range responseHeaders {
			for _, w := range wantedHeaders {
				if strings.Contains(r, w) {
					result[w] = strings.Split(r, `"`)[1]
				}
			}
		}
	}
	return result
}

func getMD5(text string) string {
	hasher := md5.New()
	hasher.Write([]byte(text))
	return hex.EncodeToString(hasher.Sum(nil))
}

func randomKey() string {
	k := make([]byte, 12)
	for bytes := 0; bytes < len(k); {
		n, err := rand.Read(k[bytes:])
		if err != nil {
			panic("rand.Read() failed")
		}
		bytes += n
	}
	return base64.StdEncoding.EncodeToString(k)
}
func getDigestAuthrization(digestParts map[string]string) string {
	d := digestParts
	ha1 := getMD5(d["username"] + ":" + d["realm"] + ":" + d["password"])
	ha2 := getMD5(d["method"] + ":" + d["uri"])
	nonceCount := "00000001"
	cnonce := randomKey()
	response := getMD5(fmt.Sprintf("%s:%s:%s:%s:%s:%s", ha1, d["nonce"], nonceCount, cnonce, d["qop"], ha2))
	authorization := fmt.Sprintf(`Digest username="%s", realm="%s", nonce="%s", uri="%s", cnonce="%s", nc=%s, qop="%s", response="%s", opaque="%s", algorithm="%s"`,
		d["username"], d["realm"], d["nonce"], d["uri"], cnonce, nonceCount, d["qop"], response, d["opaque"], d["algorithm"])
	return authorization
}
