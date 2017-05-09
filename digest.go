// Packlage digest provides a drop-in replacement for http.Client that supports HTTP Digest
// auth for GET and POST (and other) HTTP methods
package digest

import (
	"bytes"
	"crypto/md5"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// Type Client is a wrapper around http.Client
type Client struct {
	*http.Client
	User     string
	Password string
}

// NewClient returns a new digest Client instance. If c is nil, a new default
// client is created. Otherwise, it wraps the given one
func NewClient(c *http.Client, user, pass string) *Client {

	if c == nil {
		c = &http.Client{}
	}

	return &Client{Client: c, User: user, Password: pass}
}

// Get issues a GET to the specified URL. If the response is one of the
// following redirect codes, Get follows the redirect after calling the
// Client's CheckRedirect function:
//
//    301 (Moved Permanently)
//    302 (Found)
//    303 (See Other)
//    307 (Temporary Redirect)
//    308 (Permanent Redirect)
//
// An error is returned if the Client's CheckRedirect function fails
// or if there was an HTTP protocol error. A non-2xx response doesn't
// cause an error.
//
// When err is nil, resp always contains a non-nil resp.Body.
// Caller should close resp.Body when done reading from it.
//
// To make a request with custom headers, use http.NewRequest and Client.Do.
func (c *Client) Get(url string) (resp *http.Response, err error) {

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}

	return c.Do(req)

}

// Head issues a HEAD to the specified URL. If the response is one of the
// following redirect codes, Head follows the redirect after calling the
// Client's CheckRedirect function:
//
//    301 (Moved Permanently)
//    302 (Found)
//    303 (See Other)
//    307 (Temporary Redirect)
//    308 (Permanent Redirect)
func (c *Client) Head(url string) (resp *http.Response, err error) {

	req, err := http.NewRequest("HEAD", url, nil)
	if err != nil {
		return nil, err
	}

	return c.Do(req)

}

// Post issues a POST to the specified URL.
//
// Caller should close resp.Body when done reading from it.
//
// If the provided body is an io.Closer, it is closed after the
// request.
//
// To set custom headers, use http.NewRequest and Client.Do.
//
// See the Client.Do method documentation for details on how redirects
// are handled.
func (c *Client) Post(url, contentType string, body io.Reader) (resp *http.Response, err error) {

	req, err := http.NewRequest("POST", url, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", contentType)
	return c.Do(req)
}

// PostForm issues a POST to the specified URL,
// with data's keys and values URL-encoded as the request body.
//
// The Content-Type header is set to application/x-www-form-urlencoded.
// To set other headers, use NewRequest and DefaultClient.Do.
//
// When err is nil, resp always contains a non-nil resp.Body.
// Caller should close resp.Body when done reading from it.
//
// See the Client.Do method documentation for details on how redirects
// are handled.
func (c *Client) PostForm(url string, data url.Values) (resp *http.Response, err error) {
	return c.Post(url, "application/x-www-form-urlencoded", strings.NewReader(data.Encode()))
}

// Do sends an HTTP request and returns an HTTP response, following
// policy (such as redirects, cookies, auth) as configured on the
// client.
//
// If Username and Password are specified, Do performs HTTP Digest
// authentication against the web server
//
// An error is returned if caused by client policy (such as CheckRedirect), or
// failure to speak HTTP (such as a network connectivity problem). A non-2xx
// status code doesn't cause an error.
//
// If the returned error is nil, the Response will contain a non-nil Body which
// the user is expected to close. If the Body is not closed, the Client's
// underlying RoundTripper (typically Transport) may not be able to re-use a
// persistent TCP connection to the server for a subsequent "keep-alive"
// request.
//
// The request Body, if non-nil, will be closed by the underlying Transport,
// even on errors.
//
// On error, any Response can be ignored. A non-nil Response with a non-nil
// error only occurs when CheckRedirect fails, and even then the returned
// Response.Body is already closed.
//
// Generally Get, Post, or PostForm will be used instead of Do.
//
// If the server replies with a redirect, the Client first uses the
// CheckRedirect function to determine whether the redirect should be followed.
// If permitted, a 301, 302, or 303 redirect causes subsequent requests to use
// HTTP method GET (or HEAD if the original request was HEAD), with no body.  A
// 307 or 308 redirect preserves the original HTTP method and body, provided
// that the Request.GetBody function is defined.  The http.NewRequest function
// automatically sets GetBody for common standard library body types.
func (c *Client) Do(r *http.Request) (*http.Response, error) {

	// If no user/pass is set, just wrap *http.Client
	if c.User == "" && c.Password == "" {
		return c.Client.Do(r)
	}

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
