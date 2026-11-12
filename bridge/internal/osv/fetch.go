package osv

import (
	"fmt"
	"io"
	"net/http"
	"time"
)

// FetchFrom fetches the OSV advisory JSON for id from base (e.g.
// https://api.osv.dev). A missing advisory is an error.
func FetchFrom(base, id string) ([]byte, error) {
	res, err := (&http.Client{Timeout: 2 * time.Minute}).Get(base + "/v1/vulns/" + id)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	if res.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("OSV.dev has no advisory for %s", id)
	}
	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("OSV.dev %s: %s", id, res.Status)
	}
	return io.ReadAll(res.Body)
}

// Fetch fetches the advisory from the public OSV.dev API.
func Fetch(id string) ([]byte, error) {
	return FetchFrom("https://api.osv.dev", id)
}
