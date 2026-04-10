package admin

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// Client wraps HTTP calls to node admin endpoints.
type Client struct {
	NodeURL string
	APIKey  string
	HTTP    *http.Client
}

// NewClient creates a new admin Client for the given node URL.
func NewClient(nodeURL, apiKey string) *Client {
	return &Client{
		NodeURL: nodeURL,
		APIKey:  apiKey,
		HTTP:    &http.Client{Timeout: 30 * time.Second},
	}
}

func (c *Client) doJSON(method, path string, body interface{}) ([]byte, int, error) {
	var r io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return nil, 0, err
		}
		r = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, c.NodeURL+path, r)
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("Content-Type", "application/json")
	if c.APIKey != "" {
		req.Header.Set("X-Api-Key", c.APIKey)
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	return data, resp.StatusCode, err
}

// RotateKey triggers key rotation on the node.
func (c *Client) RotateKey() error {
	_, code, err := c.doJSON(http.MethodPost, "/rotate-key", nil)
	if err != nil {
		return err
	}
	if code != http.StatusOK {
		return fmt.Errorf("rotate-key returned %d", code)
	}
	return nil
}

// PurgeShares removes shares for the given objectID from the node.
func (c *Client) PurgeShares(objectID, contractID string) error {
	body := map[string]string{"object_id": objectID, "contract_id": contractID}
	_, code, err := c.doJSON(http.MethodDelete, "/shares", body)
	if err != nil {
		return err
	}
	if code != http.StatusOK {
		return fmt.Errorf("purge-shares returned %d", code)
	}
	return nil
}

// Status fetches the node status.
func (c *Client) Status() (map[string]interface{}, error) {
	data, _, err := c.doJSON(http.MethodGet, "/status", nil)
	if err != nil {
		return nil, err
	}
	var m map[string]interface{}
	return m, json.Unmarshal(data, &m)
}
