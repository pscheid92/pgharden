package hba

import "testing"

func TestClassifyAuthMethod(t *testing.T) {
	tests := []struct {
		method string
		want   AuthMethodSecurity
	}{
		{"scram-sha-256", AuthSecure},
		{"cert", AuthSecure},
		{"gss", AuthSecure},
		{"peer", AuthSecure},
		{"pam", AuthSecure},
		{"ldap", AuthSecure},
		{"radius", AuthSecure},
		{"md5", AuthWeak},
		{"ident", AuthWeak},
		{"trust", AuthForbidden},
		{"password", AuthForbidden},
		{"reject", AuthReject},
		{"unknown_method", AuthUnknown},
	}

	for _, tt := range tests {
		t.Run(tt.method, func(t *testing.T) {
			got := ClassifyAuthMethod(tt.method)
			if got != tt.want {
				t.Errorf("ClassifyAuthMethod(%q) = %d, want %d", tt.method, got, tt.want)
			}
		})
	}
}
