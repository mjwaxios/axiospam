/*
 * pamuser.go - Authenticate a User against PAM.
 *
 * Copyright 2020 Michael Wyrick
 * Author: Michael Wyirck
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy of
 * the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations under
 * the License.
 */

// Package axiospam contains functionality to Authenticate a User with
// Pluggable Authentication Modules (PAM). Currently, all this package does is
// check the validity of a user's login passphrase.
// See http://www.linux-pam.org/Linux-PAM-html/ for more information.
//
// You will need to have a pam module file called axiospam in your pam.d folder.
//  Example:
//  $cat /etc/pam.d/axiospam
//  #%PAM-1.0
//  # default for a centos system,
//  auth	   required	pam_sepermit.so
//  auth       substack     password-auth
//  auth       include      postlogin
//
//  # if we only want the local system use only this
//  #auth	required	pam_unix.so
//
// This also links to libpam so you will need to have libpam-devel installed.
// on Ubuntu the pam-devel package is called libpam0g-dev
package axiospam

import "C"

import (
	"errors"
	"fmt"
	"sync"
)

const (
	success         = 0
	authError       = 7
	authinfoUnavail = 9
	userUnknown     = 10
	newAuthtokReqd  = 12
	acctExpired     = 13
	authtokErr      = 20
)

// messages Number to Strings
var messages = []string{
	"SUCCESS",
	"OPEN_ERR",
	"SYMBOL_ERR",
	"SERVICE_ERR",
	"SYSTEM_ERR",
	"BUF_ERR",
	"PERM_DENIED",
	"AUTH_ERR",
	"CRED_INSUFFICIENT",
	"AUTHINFO_UNAVAIL",
	"USER_UNKNOWN",
	"MAXTRIES",
	"NEW_AUTHTOK_REQD",
	"ACCT_EXPIRED",
	"SESSION_ERR",
	"CRED_UNAVAIL",
	"CRED_EXPIRED",
	"CRED_ERR",
	"NO_MODULE_DATA",
	"CONV_ERR",
	"AUTHTOK_ERR",
	"AUTHTOK_RECOVERY_ERR",
	"AUTHTOK_LOCK_BUSY",
	"AUTHTOK_DISABLE_AGING",
	"TRY_AGAIN",
	"IGNORE",
	"ABORT",
	"AUTHTOK_EXPIRED",
	"MODULE_UNKNOWN",
	"BAD_ITEM",
	"CONV_AGAIN",
	"INCOMPLETE",
}

// PamResult is the result of a call to Authenticate
type PamResult int

const (
	// Uninitialized is the zero value
	Uninitialized PamResult = iota
	// SystemError can happen if pam is not setup correctly or the application does not have permission for the user in question
	SystemError
	// Authenticated Username and Password are Valid and no flags on the account
	Authenticated
	// UnknownUser means the Username is Unknown to the pam system
	UnknownUser
	// AuthError can happen if the password is incorrect, the account is locked, etc.
	AuthError
	// PasswordExpired means Username and Password are Valid but the system indicates the Password has expired
	PasswordExpired
	// AccountExpired means Username and Password are Valid but the system indicates the Account has expired
	AccountExpired
	// UnknownFlag is a catchall for a pam account flag we don't know about
	UnknownFlag
	// AuthTokError means the New password does not meet requirements or there was a problem updating the Auth Token
	AuthTokError
	// InvalidoldPassword means the Old password is invalid
	InvalidoldPassword
	// Success means the password was changed
	Success
)

func (s PamResult) String() string {
	if s < Uninitialized || s > Success {
		return "unknown AuthenResult"
	}

	return [...]string{"uninitialized", "system error", "authenticated", "unknown user",
		"auth error", "password expired", "account expired", "unknown account flag",
		"unable to update auth token", "invalid old password", "success"}[s]
}

func (s PamResult) Error() string {
	return "pam error: " + s.String()
}

// AccountFlags get the User Account Flags from Pam
func AccountFlags(name string) (int, error) {
	flags, err := getUserAccountFlags(name, true)
	return flags, err
}

// Authenticate takes the username and password and checks it with PAM
func Authenticate(name, password string) (PamResult, error) {
	// Check that we can get the Account Info for this user,
	// we will also check the flags again after we authenticate
	Flags, _ := getUserAccountFlags(name, true)
	switch Flags {
	case success:
		break
	case userUnknown:
		return UnknownUser, UnknownUser
	case newAuthtokReqd:
		break
	case acctExpired:
		return AccountExpired, AccountExpired
	default:
		return SystemError, UnknownFlag
	}

	a, err := isUserLoginToken(name, password, false)
	if err != nil {
		return SystemError, err
	}

	// Did not Authenticate and did not have an error
	if a == false {
		return AuthError, AuthError
	}

	// We are Authenticated from this point on

	// We Are Valid, so check if we should return any flags for the account
	Flags, _ = getUserAccountFlags(name, true)
	switch Flags {
	case success:
		return Authenticated, nil
	case newAuthtokReqd:
		return PasswordExpired, nil
	case acctExpired:
		return AccountExpired, nil
	default:
		return SystemError, UnknownFlag
	}
}

// ChangePassword will call the pam system to change the users password
func ChangePassword(name, oldPassword, newPassword string) (PamResult, error) {
	// Check that we can get the Account Info for this user,
	Flags, _ := getUserAccountFlags(name, true)
	switch Flags {
	case success:
		break
	case userUnknown:
		return UnknownUser, UnknownUser
	case newAuthtokReqd:
		break
	case acctExpired:
		break
	default:
		return SystemError, UnknownFlag
	}

	// Continue to Change Password
	status, err := changeToken(name, oldPassword, newPassword, false)

	if err != nil {
		return SystemError, err
	}

	switch status {
	case success:
		return Success, nil
	case authError:
		return InvalidoldPassword, InvalidoldPassword
	case authtokErr:
		return AuthTokError, AuthTokError
	default:
		return SystemError, errors.New("unknown status")
	}
}

// ------------------------------------------------------------------------------------
// Private Functtions to call the pam C interface
// ------------------------------------------------------------------------------------

// Pam error values
var (
	errPassphrase = errors.New("incorrect login")
)

// Global state is needed for the PAM callback, so we guard this function with a
// lock. tokenToCheck is only ever non-nil when tokenLock is held.
var (
	tokenLock    sync.Mutex
	tokenToCheck string
	tokenToSet   string
)

// userInput is run when the callback needs some input from the user. We prompt
// the user for information and return their answer. A return value of nil
// indicates an error occurred.
//export userInput
func userInput(prompt *C.char) *C.char {
	s := C.GoString(prompt)
	if s != "" {
		fmt.Println(s)
	}
	return C.CString("")
}

// passphraseInput is run when the callback needs a passphrase from the user. We
// pass along the tokenToCheck without prompting. A return value of nil
// indicates an error occurred.
//export passphraseInput
func passphraseInput(prompt *C.char) *C.char {
	s := C.GoString(prompt)
	if s != "" {
		fmt.Print(s)
	}
	// Subsequent calls to passphrase input should fail
	fmt.Println(tokenToCheck)
	input := (*C.char)(C.CString(tokenToCheck))
	tokenToCheck = tokenToSet

	return input
}

// IsUserLoginToken returns nil if the presented token is the user's login key,
// and returns an error otherwise. Note that unless we are currently running as
// root, this check will only work for the user running this process.
func isUserLoginToken(username string, password string, quiet bool) (bool, error) {
	// We require global state for the function. This function never takes
	// ownership of the token, so it is not responsible for wiping it.
	tokenLock.Lock()
	tokenToCheck = password
	tokenToSet = ""
	defer func() {
		tokenToCheck = ""
		tokenToSet = ""
		tokenLock.Unlock()
	}()

	transaction, err := start("axiospam", username)
	if err != nil {
		return false, err
	}
	defer transaction.End()

	// Ask PAM to authenticate the token.
	authenticated, err := transaction.authenticate(quiet)
	if err != nil {
		return false, err
	}

	if !authenticated {
		return false, nil
	}
	return true, nil
}

// changeToken will change the users password
func changeToken(username, oldpassword, newpassword string, quiet bool) (int, error) {
	// We require global state for the function. This function never takes
	// ownership of the token, so it is not responsible for wiping it.
	tokenLock.Lock()
	tokenToCheck = oldpassword
	tokenToSet = newpassword
	defer func() {
		tokenToCheck = ""
		tokenToSet = ""
		tokenLock.Unlock()
	}()

	transaction, err := start("axiospam", username)
	if err != nil {
		return 5, err
	}
	defer transaction.End()

	// Ask PAM to authenticate the old Token First
	authenticated, err := transaction.authenticate(quiet)
	if err != nil {
		return -1, err
	}

	if !authenticated {
		return authError, nil
	}

	tokenToCheck = oldpassword
	tokenToSet = newpassword

	// Ask PAM to change the token.
	status, err := transaction.changeTok(quiet)
	return status, err
}

// get the User Account Flags from PAM
func getUserAccountFlags(username string, quiet bool) (int, error) {
	transaction, err := start("axiospam", username)
	if err != nil {
		return 0, err
	}
	defer transaction.End()

	// Ask PAM to authenticate the token.
	flags, err := transaction.accountManagement(quiet)
	if err != nil {
		return 0, err
	}

	return flags, nil
}
