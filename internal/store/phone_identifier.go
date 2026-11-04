package store

// PhoneIdentifierActive is shared by stores and authentication writers.
func PhoneIdentifierActive(c *Connection) bool {
	if c == nil || c.Strategy != StrategyDatabase {
		return false
	}
	attrs, _ := c.Extra["attributes"].(map[string]any)
	p, _ := attrs["phone_number"].(map[string]any)
	id, _ := p["identifier"].(map[string]any)
	active, _ := id["active"].(bool)
	return active
}

// IdentifierAttribute returns the flexible identifier's configured signup rule.
func IdentifierAttribute(c *Connection, name string) map[string]any {
	attrs, _ := c.Extra["attributes"].(map[string]any)
	v, _ := attrs[name].(map[string]any)
	return v
}

func IdentifierActive(c *Connection, name string) bool {
	attrs := IdentifierAttribute(c, name)
	id, _ := attrs["identifier"].(map[string]any)
	if active, ok := id["active"].(bool); ok {
		return active
	}
	switch name {
	case "email":
		return true
	case "username":
		return c.RequiresUsername
	case "phone_number":
		return false
	}
	return false
}
func IdentifierPrecedence(c *Connection) []string {
	var out []string
	switch v := c.Extra["precedence"].(type) {
	case []any:
		for _, x := range v {
			if s, ok := x.(string); ok {
				out = append(out, s)
			}
		}
	case []string:
		out = append(out, v...)
	}
	if len(out) == 0 {
		return []string{"email", "username", "phone_number"}
	}
	return out
}

func PhoneSignupStatus(c *Connection) string {
	signup, _ := IdentifierAttribute(c, "phone_number")["signup"].(map[string]any)
	status, _ := signup["status"].(string)
	return status
}
func PhoneSignupVerification(c *Connection) bool {
	signup, _ := IdentifierAttribute(c, "phone_number")["signup"].(map[string]any)
	verification, _ := signup["verification"].(map[string]any)
	if active, ok := verification["active"].(bool); ok {
		return active
	}
	return true
}
