// Packlage digest provides a wrapper for http.Client that supports HTTP Digest
// auth for GET and POST (and other) HTTP methods
package digest

import (
	"bytes"
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

// NewAuthClient returns a new AuthClient instance. If c is nil, a new default
// client is created. Otherwise, it wraps the given one
func NewAuthClient(c *http.Client, user, pass string) *AuthClient {

	if c == nil {
		c = &http.Client{}
	}

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

	resp, err := c.Client.Do(initreq)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusUnauthorized {
		// No auth necessary
		// redo the request with the body if needed
		if r.Method != "GET" || r.Body != nil {
			resp, err = c.Client.Do(r)
		}
	} else {

		digestParts := digestParts(r, resp)
		digestParts["uri"] = r.URL.Path
		digestParts["method"] = r.Method
		digestParts["username"] = c.User
		digestParts["password"] = c.Password
		r.Header.Set("Authorization", getDigestAuth(digestParts, r))

		resp, err = c.Client.Do(r)
	}

	return resp, err
}

func digestParts(req *http.Request, resp *http.Response) (res map[string]string) {

	res = make(map[string]string)

	// 'qop' header can be 'auth, auth-int', so need to handle that. Only use auth-int if body is not null

	if len(resp.Header["Www-Authenticate"]) > 0 {
		wantedHeaders := []string{"nonce", "realm", "qop", "algorithm", "opaque"}
		responseHeaders := strings.Split(resp.Header["Www-Authenticate"][0], ",")
		for _, r := range responseHeaders {
			r = strings.TrimSpace(r)
			for _, w := range wantedHeaders {
				if strings.Contains(r, w) {
					res[w] = strings.Split(r, `"`)[1]
					if w == "qop" {
						if strings.Contains(res[w], "auth-int") && req.Body != nil {
							res[w] = "auth-int"
						} else if strings.Contains(res[w], "auth") {
							res[w] = "auth"
						}
					}
				}
			}
		}
	}
	return res
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

func getDigestAuth(d map[string]string, r *http.Request) (auth string) {

	var ha1 string
	var ha2 string

	cnonce := randomKey()

	//ha1
	switch d["algorithm"] {
	case "MD5":
		ha1 = getMD5(fmt.Sprintf("%s:%s:%s", d["username"], d["realm"], d["password"]))
	case "MD5-sess":
		ha1 = getMD5(fmt.Sprintf("%s:%s:%s",
			getMD5(fmt.Sprintf("%s:%s:%s", d["username"], d["realm"], d["password"])),
			d["nonce"], cnonce))
	}

	// ha2
	switch d["qop"] {
	case "auth-int":
		buf := new(bytes.Buffer)
		buf.ReadFrom(r.Body)
		s := buf.String()
		ha2 = getMD5(fmt.Sprintf("%s:%s:%s", d["method"], d["uri"], getMD5(s)))
	case "auth", "":
		ha2 = getMD5(fmt.Sprintf("%s:%s", d["method"], d["uri"]))
	}

	var response string
	nonceCount := 1

	// determine response
	switch d["qop"] {
	case "auth", "auth-int":
		response = getMD5(fmt.Sprintf("%s:%s:%08d:%s:%s:%s", ha1, d["nonce"], nonceCount, cnonce, d["qop"], ha2))
	case "":
		response = getMD5(fmt.Sprintf("%s:%s:%s", ha1, d["nonce"], ha2))
	}

	auth = fmt.Sprintf(`Digest username="%s", realm="%s", nonce="%s", uri="%s", cnonce="%s", nc=%08d, qop="%s", response="%s", opaque="%s", algorithm="%s"`,
		d["username"], d["realm"], d["nonce"], d["uri"], cnonce, nonceCount, d["qop"], response, d["opaque"], d["algorithm"])
	return auth
}
