package email

import (
	"bytes"
	htmltemplate "html/template"
	"strconv"
	texttemplate "text/template"

	"github.com/zeroauthy/zeroauthy/internal/i18n"
)

var (
	importDoneText = texttemplate.Must(texttemplate.New("import_done.txt").
			Funcs(texttemplate.FuncMap{"t": tr}).ParseFS(templateFS, "templates/import_done.txt"))
	importDoneHTML = htmltemplate.Must(htmltemplate.New("import_done.html").
			Funcs(htmltemplate.FuncMap{"t": tr}).ParseFS(templateFS, "templates/import_done.html"))
)

// ImportDone is what the user import completion email reports.
type ImportDone struct {
	Tenant, Job, Connection string
	// Failed is a job that ended failed, with Details its status_details;
	// otherwise the counts are its summary.
	Failed  bool
	Details string

	Inserted, Updated, FailedRecords, Total int
}

// ImportDoneMessage renders the email that tells an operator a user import
// ended, in l's language. The caller sets To.
func ImportDoneMessage(l *i18n.Localizer, d ImportDone) Message {
	l = l.WithVar("tenant", d.Tenant).WithVar("job", d.Job).WithVar("connection", d.Connection).
		WithVar("details", d.Details).WithVar("inserted", strconv.Itoa(d.Inserted)).
		WithVar("updated", strconv.Itoa(d.Updated)).WithVar("failed", strconv.Itoa(d.FailedRecords)).
		WithVar("total", strconv.Itoa(d.Total))
	data := struct {
		L      *i18n.Localizer
		Failed bool
	}{l, d.Failed}
	var txt, htm bytes.Buffer
	// The templates are embedded and the data is plain strings, so
	// execution cannot fail.
	if err := importDoneText.Execute(&txt, data); err != nil {
		panic(err)
	}
	if err := importDoneHTML.Execute(&htm, data); err != nil {
		panic(err)
	}
	subject := i18n.KeyEmailImportDoneSubject
	if d.Failed {
		subject = i18n.KeyEmailImportFailedSubject
	}
	return Message{Subject: l.T(subject), Text: txt.String(), HTML: htm.String()}
}
