package adhub

// Hub holds the connector sockets of this replica (Task 3).
type Hub struct{}

// Evict closes the connection's sockets whose certificate thumbprint is not
// in keep (LR38a-5).
func (h *Hub) Evict(tenantID, connectionID string, keep []string) {}
