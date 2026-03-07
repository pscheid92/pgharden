package hba

import "github.com/pgharden/pgharden/internal/checker"

// Entry is an alias for checker.HBAEntry.
type Entry = checker.HBAEntry

// AuthMethodSecurity classifies authentication methods.
type AuthMethodSecurity int

const (
	AuthSecure    AuthMethodSecurity = iota // scram-sha-256, cert, gss, sspi, pam, ldap, radius
	AuthWeak                                // md5, ident
	AuthForbidden                           // trust, password
	AuthReject                              // reject
	AuthUnknown
)

// ClassifyAuthMethod returns the security classification of an auth method.
func ClassifyAuthMethod(method string) AuthMethodSecurity {
	switch method {
	case "scram-sha-256", "cert", "gss", "sspi", "pam", "ldap", "radius":
		return AuthSecure
	case "peer":
		return AuthSecure
	case "md5", "ident":
		return AuthWeak
	case "trust", "password":
		return AuthForbidden
	case "reject":
		return AuthReject
	default:
		return AuthUnknown
	}
}
