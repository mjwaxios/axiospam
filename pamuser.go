package axiospam

// PAMUser Hold a PAM user to authenticate
type PAMUser struct {
	Username      string
	Password      string
	Authenticated bool
	ErrorReason   error
}

// Authenticate takes a username and password and return the results of PAM auth
func (user *PAMUser) Authenticate() (result bool, err error) {
	result = false
	user.Authenticated = false
	e := IsUserLoginToken(user.Username, user.Password, true)
	user.ErrorReason = e
	if e != nil {
		return false, e
	}
	user.Authenticated = true
	return true, nil
}
