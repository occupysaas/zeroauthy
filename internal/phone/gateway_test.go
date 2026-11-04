package phone

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestGatewayTestEndpointOverridesOnlyTestTransport(t *testing.T) {
	oldEndpoints, oldTest := Endpoints, testEndpoints
	t.Cleanup(func() { Endpoints, testEndpoints = oldEndpoints, oldTest })
	hits := 0
	fake := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits++; w.WriteHeader(http.StatusOK) }))
	defer fake.Close()
	SetTestEndpoints("", "", fake.URL+"/gateway")
	sender := NewGateway(GatewayConfig{URL: "https://gateway.e2e.test/gateway"}, fake.Client(), nil)
	if _, err := sender.Send(context.Background(), Message{To: "+14155553412", Body: "Code 123456", DeliveryMethod: "text"}); err != nil {
		t.Fatal(err)
	}
	if hits != 1 {
		t.Fatalf("local gateway deliveries=%d", hits)
	}
}
