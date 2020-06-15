package middleware

import (
	"github.com/gol4ng/httpware/v2"
	"github.com/gol4ng/httpware/v2/middleware"
	"github.com/gol4ng/security"
	authentication_http "github.com/gol4ng/security-http/authentication"
	"github.com/gol4ng/security/authentication"
	"github.com/gol4ng/security/user_password"
)

const DefaultRealm = "Restricted area"

func Authentication(authenticator security.Authenticator, options ...middleware.AuthOption) httpware.Middleware {
	return middleware.Authentication(
		authentication_http.NewAuthenticatorAdapter(authenticator),
		options...
	)
}

func DefaultBasicAuthentication(provider security.UserProvider, checker user_password.TokenChecker) httpware.Middleware {
	return Authentication(
		authentication.NewBasicAuthenticator(provider, checker),
		middleware.WithCredentialFinder(AuthorizationHeader),
		middleware.WithErrorHandler(BasicErrorHandler(DefaultRealm, false)),
	)
}
