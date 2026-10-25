package providers

// Message is the provider-neutral envelope rendered by the email service.
type Message struct{ From, To, Subject, Text, HTML string }
