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
//  auth	   required	Pamsepermit.so
//  auth       substack     password-auth
//  auth       include      postlogin
//
//  # if we only want the local system use only this
//  #auth	required	Pamunix.so
//
// This also links to libpam so you will need to have libpam-devel installed.
// on Ubuntu the pam-devel package is called libpam0g-dev
package axiospam

import "C"

import (
	"errors"
	//	"fmt"
	"sync"
)

var (
	errUnknownFlag = errors.New("unknown flag on account")
)

// PamResult is the result of a call to Authenticate
type PamResult int

const (
	PamSuccess             PamResult = 0  /* Successful function return */
	PamOpenERR             PamResult = 1  /* dlopen() failure when dynamically */
	PamSymbolERR           PamResult = 2  /* Symbol not found */
	PamServiceERR          PamResult = 3  /* Error in service module */
	PamSystemERR           PamResult = 4  /* System error */
	PamBufERR              PamResult = 5  /* Memory buffer error */
	PamPermDenied          PamResult = 6  /* Permission denied */
	PamAuthERR             PamResult = 7  /* Authentication failure */
	PamCredInsufficient    PamResult = 8  /* Can not access authentication data */
	PamAuthInfoUnavail     PamResult = 9  /* Underlying authentication service */
	PamUserUnknown         PamResult = 10 /* User not known to the underlying */
	PamMaxTries            PamResult = 11 /* An authentication service has */
	PamNewAuthTokReqd      PamResult = 12 /* New authentication token required. */
	PamAcctExpired         PamResult = 13 /* User account has expired */
	PamSessiionERR         PamResult = 14 /* Can not make/remove an entry for */
	PamCredUnavail         PamResult = 15 /* Underlying authentication service */
	PamCredExpired         PamResult = 16 /* User credentials expired */
	PamCredERR             PamResult = 17 /* Failure setting user credentials */
	PamNoModuleData        PamResult = 18 /* No module specific data is present */
	PamConvERR             PamResult = 19 /* Conversation error */
	PamAuthTokERR          PamResult = 20 /* Authentication token manipulation error */
	PamAuthTokRecoveryERR  PamResult = 21 /* Authentication information */
	PamAuthTokLockBusy     PamResult = 22 /* Authentication token lock busy */
	PamAuthTokDisableAging PamResult = 23 /* Authentication token aging disabled */
	PamTryAgain            PamResult = 24 /* Preliminary check by password service */
	PamIgnore              PamResult = 25 /* Ignore underlying account module */
	PamAbort               PamResult = 26 /* Critical error (?module fail now request) */
	PamAuthTokExpired      PamResult = 27 /* user's authentication token has expired */
	PamModuleUnknown       PamResult = 28 /* module is not known */
	PamBadItem             PamResult = 29 /* Bad item passed to Pam*_item() */
	PamConvAgain           PamResult = 30 /* conversation function is event driven and data is not available yet */
	PamIncomplete          PamResult = 31 /* please call this function again to */
)

// messages Number to Strings
var messages = [...]string{
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

// String will convert a PamResult to a String
func (s PamResult) String() string {
	if int(s) < 0 || int(s) > len(messages) {
		return "unknown AuthenResult"
	}

	return messages[s]
}

// Error will let use use a PamResult as an Error, will use string to make it a String
func (s PamResult) Error() string {
	return "pam error: " + s.String()
}

// AccountFlags get the User Account Flags from Pam
func AccountFlags(name string) (PamResult, error) {
	flags, err := getUserAccountFlags(name, true)
	return flags, err
}

// Authenticate takes the username and password and checks it with PAM
func Authenticate(name, password string) (PamResult, error) {
	// Check that we can get the Account Info for this user,
	// we will also check the flags again after we authenticate
	Flags, _ := getUserAccountFlags(name, true)

	switch Flags {
	case PamSuccess, PamNewAuthTokReqd, PamAuthTokExpired:
		break
	case PamAuthInfoUnavail, PamUserUnknown, PamAcctExpired:
		return PamAuthERR, Flags
	default:
		return PamSystemERR, errUnknownFlag
	}

	a, err := isUserLoginToken(name, password, false)
	if err != nil {
		return PamSystemERR, err
	}

	// Did not Authenticate and did not have an error
	// We return an AuthERR and the result from the pam call might have more information
	if a != PamSuccess {
		return PamAuthERR, a
	}

	// We are Authenticated from this point on

	// We Are Valid, so check if we should return any flags for the account
	Flags, _ = getUserAccountFlags(name, true)

	switch Flags {
	case PamSuccess, PamNewAuthTokReqd, PamAcctExpired:
		return Flags, nil
	}

	return PamSystemERR, errUnknownFlag
}

// ChangePassword will call the pam system to change the users password
func ChangePassword(name, oldPassword, newPassword string) (PamResult, error) {
	// Check that we can get the Account Info for this user,
	Flags, _ := getUserAccountFlags(name, true)

	switch Flags {
	case PamSuccess, PamNewAuthTokReqd, PamAcctExpired:
		break
	case PamUserUnknown, PamAuthInfoUnavail:
		return PamAuthERR, Flags
	default:
		return PamSystemERR, errUnknownFlag
	}

	// Continue to Change Password
	status, err := changeToken(name, oldPassword, newPassword, false)
	if err != nil {
		return PamSystemERR, err
	}

	switch status {
	case PamSuccess:
		return PamSuccess, nil
	case PamAuthERR, PamAuthTokERR:
		return status, status
	}

	return PamSystemERR, errUnknownFlag
}

// ------------------------------------------------------------------------------------
// Private Functtions to call the pam C interface
// ------------------------------------------------------------------------------------

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
	//	s := C.GoString(prompt)
	//	if s != "" {
	//		fmt.Println(s)
	//	}
	return C.CString("")
}

// passphraseInput is run when the callback needs a passphrase from the user. We
// pass along the tokenToCheck without prompting. A return value of nil
// indicates an error occurred.
//export passphraseInput
func passphraseInput(prompt *C.char) *C.char {
	//	s := C.GoString(prompt)
	//	if s != "" {
	//		fmt.Print(s)
	//	}
	// Subsequent calls to passphrase input should fail
	//	fmt.Println(tokenToCheck)
	input := (*C.char)(C.CString(tokenToCheck))
	tokenToCheck = tokenToSet

	return input
}

// IsUserLoginToken returns nil if the presented token is the user's login key,
// and returns an error otherwise. Note that unless we are currently running as
// root, this check will only work for the user running this process.
func isUserLoginToken(username string, password string, quiet bool) (PamResult, error) {
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
		return PamSystemERR, err
	}
	defer transaction.End()

	// Ask PAM to authenticate the token.
	authenticated, err := transaction.authenticate(quiet)
	if err != nil {
		return PamSystemERR, err
	}

	if authenticated {
		return PamSuccess, nil
	}

	return PamAuthERR, nil
}

// changeToken will change the users password
func changeToken(username, oldpassword, newpassword string, quiet bool) (PamResult, error) {
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
		return PamSystemERR, err
	}
	defer transaction.End()

	// Ask PAM to authenticate the old Token First
	if authenticated, err := transaction.authenticate(quiet); err != nil {
		return PamSystemERR, err
	} else if !authenticated {
		return PamAuthERR, nil
	}

	tokenToSet = newpassword

	// Ask PAM to change the token.
	status, err := transaction.changeTok(quiet)
	return PamResult(status), err
}

// get the User Account Flags from PAM
func getUserAccountFlags(username string, quiet bool) (PamResult, error) {
	transaction, err := start("axiospam", username)
	if err != nil {
		return PamSystemERR, err
	}
	defer transaction.End()

	// Ask PAM to authenticate the token.
	flags, err := transaction.accountManagement(quiet)
	if err != nil {
		return PamSystemERR, err
	}

	return PamResult(flags), nil
}
