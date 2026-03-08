package hba

import "github.com/pscheid92/pgharden/internal/domain"

type Entry = domain.HBAEntry

type AuthMethodSecurity int

const (
	AuthSecure AuthMethodSecurity = iota
	AuthWeak
	AuthForbidden
	AuthReject
	AuthUnknown
)

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
