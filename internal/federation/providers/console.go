package providers

import "encoding/json"

// ConsoleDescriptor is what the console needs to render one descriptor
// strategy's settings: no endpoint or credential.
type ConsoleDescriptor struct {
	Strategy    string   `json:"strategy"`
	DisplayName string   `json:"display_name"`
	Separator   string   `json:"separator"`
	BaseScopes  []string `json:"base_scopes"`
	Flags       []Flag   `json:"flags"`
	Freeform    bool     `json:"freeform_scopes"`
	// Fields are the extra options the form shows: community_base_url
	// (salesforce-community), protocol (twitter), login_hint (shopify, a
	// note: the shop comes from /authorize).
	Fields []string `json:"fields"`
}

// ConsoleSummary renders every descriptor for the console, sorted by
// strategy, as indented JSON with a trailing newline.
func ConsoleSummary() ([]byte, error) {
	out := []ConsoleDescriptor{}
	for _, d := range All() {
		c := ConsoleDescriptor{Strategy: d.Strategy, DisplayName: d.DisplayName, Separator: d.Separator(), BaseScopes: d.BaseScopes,
			Flags: d.Flags, Freeform: d.FreeformScopes, Fields: []string{}}
		switch {
		case d.Strategy == "salesforce-community":
			c.Fields = append(c.Fields, "community_base_url")
		case d.Hook == HookTwitter:
			c.Fields = append(c.Fields, "protocol")
		case d.Hook == HookShopify:
			c.Fields = append(c.Fields, "login_hint")
		}
		out = append(out, c)
	}
	b, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(b, '\n'), nil
}
