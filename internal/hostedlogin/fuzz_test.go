package hostedlogin

import "testing"

func FuzzValidateSource(f *testing.F) {
	f.Add(`<html><head>{% auth0:head %}</head><body>{% auth0:widget %}</body></html>`, false)
	f.Add(`<input name="ulp-note" type="text">`, true)
	f.Add(`<style>.za-decoration {color:rgba(1,2,3,.5)}</style>`, true)
	f.Fuzz(func(t *testing.T, source string, partial bool) { _ = ValidateSource(source, partial) })
}

func FuzzValidateCSS(f *testing.F) {
	f.Add(`.za-decoration {color:#112233}`)
	f.Add(`.za-decoration {margin:-1px}`)
	f.Fuzz(func(t *testing.T, source string) { _ = ValidateCSS(source) })
}
