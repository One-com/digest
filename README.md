

# digest
`import "digest"`

* [Overview](#pkg-overview)
* [Index](#pkg-index)

## <a name="pkg-overview">Overview</a>
Packlage digest provides a drop-in replacement for http.Client that supports HTTP Digest
auth for GET and POST (and other) HTTP methods




## <a name="pkg-index">Index</a>
* [type Client](#Client)
  * [func NewClient(c *http.Client, user, pass string) *Client](#NewClient)
  * [func (c *Client) Do(r *http.Request) (resp *http.Response, err error)](#Client.Do)
  * [func (c *Client) Get(url string) (resp *http.Response, err error)](#Client.Get)
  * [func (c *Client) Head(url string) (resp *http.Response, err error)](#Client.Head)
  * [func (c *Client) Post(url, contentType string, body io.Reader) (resp *http.Response, err error)](#Client.Post)
  * [func (c *Client) PostForm(url string, data url.Values) (resp *http.Response, err error)](#Client.PostForm)


#### <a name="pkg-files">Package files</a>
[digest.go](/src/digest/digest.go) 






## <a name="Client">type</a> [Client](/src/target/digest.go?s=337:407#L9)
``` go
type Client struct {
    *http.Client
    User     string
    Password string
}
```
Type Client is a wrapper around http.Client







### <a name="NewClient">func</a> [NewClient](/src/target/digest.go?s=543:600#L17)
``` go
func NewClient(c *http.Client, user, pass string) *Client
```
NewClient returns a new digest Client instance. If c is nil, a new default
client is created. Otherwise, it wraps the given one





### <a name="Client.Do">func</a> (\*Client) [Do](/src/target/digest.go?s=4958:5027#L144)
``` go
func (c *Client) Do(r *http.Request) (resp *http.Response, err error)
```
Do sends an HTTP request and returns an HTTP response, following
policy (such as redirects, cookies, auth) as configured on the
client.

If Username and Password are specified, Do performs HTTP Digest
authentication against the web server

An error is returned if caused by client policy (such as CheckRedirect), or
failure to speak HTTP (such as a network connectivity problem). A non-2xx
status code doesn't cause an error.

If the returned error is nil, the Response will contain a non-nil Body which
the user is expected to close. If the Body is not closed, the Client's
underlying RoundTripper (typically Transport) may not be able to re-use a
persistent TCP connection to the server for a subsequent "keep-alive"
request.

The request Body, if non-nil, will be closed by the underlying Transport,
even on errors.

On error, any Response can be ignored. A non-nil Response with a non-nil
error only occurs when CheckRedirect fails, and even then the returned
Response.Body is already closed.

Generally Get, Post, or PostForm will be used instead of Do.

If the server replies with a redirect, the Client first uses the
CheckRedirect function to determine whether the redirect should be followed.
If permitted, a 301, 302, or 303 redirect causes subsequent requests to use
HTTP method GET (or HEAD if the original request was HEAD), with no body.  A
307 or 308 redirect preserves the original HTTP method and body, provided
that the Request.GetBody function is defined.  The http.NewRequest function
automatically sets GetBody for common standard library body types.




### <a name="Client.Get">func</a> (\*Client) [Get](/src/target/digest.go?s=1383:1448#L44)
``` go
func (c *Client) Get(url string) (resp *http.Response, err error)
```
Get issues a GET to the specified URL. If the response is one of the
following redirect codes, Get follows the redirect after calling the
Client's CheckRedirect function:


	301 (Moved Permanently)
	302 (Found)
	303 (See Other)
	307 (Temporary Redirect)
	308 (Permanent Redirect)

An error is returned if the Client's CheckRedirect function fails
or if there was an HTTP protocol error. A non-2xx response doesn't
cause an error.

When err is nil, resp always contains a non-nil resp.Body.
Caller should close resp.Body when done reading from it.

To make a request with custom headers, use http.NewRequest and Client.Do.




### <a name="Client.Head">func</a> (\*Client) [Head](/src/target/digest.go?s=1877:1943#L64)
``` go
func (c *Client) Head(url string) (resp *http.Response, err error)
```
Head issues a HEAD to the specified URL. If the response is one of the
following redirect codes, Head follows the redirect after calling the
Client's CheckRedirect function:


	301 (Moved Permanently)
	302 (Found)
	303 (See Other)
	307 (Temporary Redirect)
	308 (Permanent Redirect)




### <a name="Client.Post">func</a> (\*Client) [Post](/src/target/digest.go?s=2395:2490#L86)
``` go
func (c *Client) Post(url, contentType string, body io.Reader) (resp *http.Response, err error)
```
Post issues a POST to the specified URL.

Caller should close resp.Body when done reading from it.

If the provided body is an io.Closer, it is closed after the
request.

To set custom headers, use http.NewRequest and Client.Do.

See the Client.Do method documentation for details on how redirects
are handled.




### <a name="Client.PostForm">func</a> (\*Client) [PostForm](/src/target/digest.go?s=3110:3197#L107)
``` go
func (c *Client) PostForm(url string, data url.Values) (resp *http.Response, err error)
```
PostForm issues a POST to the specified URL,
with data's keys and values URL-encoded as the request body.

The Content-Type header is set to application/x-www-form-urlencoded.
To set other headers, use NewRequest and DefaultClient.Do.

When err is nil, resp always contains a non-nil resp.Body.
Caller should close resp.Body when done reading from it.

See the Client.Do method documentation for details on how redirects
are handled.








- - -
Generated by [godoc2md](http://godoc.org/github.com/davecheney/godoc2md)
