package digest_test

import (
	"digest"
	"fmt"
	"net/http"
	"net/http/httputil"
	"strings"
)

// ExampleDo demonstrates how AuthClient is a drop-in replacement for http.Client
func Example_Do() {

	url := "http://posttestserver.com/post.php"
	method = "POST"
	body := strings.NewReader(`{"key":"value"}`)

	client := &http.Client{}

	request, err := http.NewRequest(method, url, body)
	if err != nil {
		panic(err)
	}

	request.Header.Set("Content-Type", "application/json")

	username := "JohnnyBravo"
	password := "OhMomma!"

	authclient := digest.NewAuthClient(client, username, password)

	resp, err := ac.Do(request)
	if err != nil {
		panic(err)
	}

	b, err = httputil.DumpResponse(resp, true)
	if err != nil {
		panic(err)
	}
	fmt.Printf("%s", string(b))

}
