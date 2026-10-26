package hostedlogin

import (
	"fmt"
	"strings"
	"testing"
)

func TestPartialFieldLimits(t *testing.T) {
	if ValidatePartials(map[string]map[string]string{"login": {"form-footer-start": `<input name="ulp-note">`}}) == nil {
		t.Fatal("control accepted in footer")
	}
	if ValidatePartials(map[string]map[string]string{"login": {"form-content-start": `<input name="ulp-note">`}, "signup": {"form-content-start": `<input name="ulp-note">`}}) == nil {
		t.Fatal("duplicate field across screens accepted")
	}
	if err := ValidatePartials(map[string]map[string]string{"login": {"form-content-start": `<input name="ulp-note">`}}); err != nil {
		t.Fatal(err)
	}
	var fields strings.Builder
	for i := 0; i < 31; i++ {
		fmt.Fprintf(&fields, `<input name="ulp-field%d">`, i)
	}
	if ValidatePartials(map[string]map[string]string{"login": {"form-content-start": fields.String()}}) == nil {
		t.Fatal("31 fields accepted")
	}
}
