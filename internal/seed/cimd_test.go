package seed

import (
	"strings"
	"testing"
)

func TestSeedCIMDClients(t *testing.T) {
	f, err := Parse([]byte(`
tenants:
  - name: a
    settings: {client_id_metadata_document_supported: true}
    cimd_clients: ["https://agent.example/client.json"]
  - name: b
`))
	if err != nil {
		t.Fatal(err)
	}
	got := f.CIMDClients()
	if len(got) != 1 || len(got["a"]) != 1 || got["a"][0] != "https://agent.example/client.json" {
		t.Fatalf("CIMDClients = %v", got)
	}
	for _, bad := range []string{"http://agent.example/client.json", "https://agent.example/", "https://agent.example/c#x"} {
		_, err := Parse([]byte("tenants: [{name: a, cimd_clients: [\"" + bad + "\"]}]"))
		if err == nil || !strings.Contains(err.Error(), "cimd_clients") {
			t.Errorf("%s: %v", bad, err)
		}
	}
}
