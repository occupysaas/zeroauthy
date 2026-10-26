package hostedlogin

import "testing"

func TestCSSPolicyNumericBounds(t *testing.T) {
	for _, source := range []string{
		`.za-decoration {color:rgb(999, 2, 3)}`,
		`.za-decoration {color:rgba(2, 3, 4, 2)}`,
		`.za-decoration {font-size:49px}`,
		`.za-decoration {padding:-1px}`,
		`.za-decoration, body {color:#112233}`,
		`.za-decoration {color:rgb(1,2)}`,
	} {
		if ValidateCSS(source) == nil {
			t.Errorf("accepted %q", source)
		}
	}
	if err := ValidateCSS(`.za-decoration {color:rgba(1, 2, 3, 0.5);font-size:48px;padding:64px}`); err != nil {
		t.Fatal(err)
	}
}
