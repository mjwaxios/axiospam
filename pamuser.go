package axiospam

// PAMUser User  Hold a PAM user to authenticate
type PAMUser struct {
	Username      string
	Password      string
	Authenticated bool
	ErrorReason   error
}

// ValidateUser takes a username and password and return the results of PAM auth
func ValidateUser(user *PAMUser) (result bool, err error) {
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