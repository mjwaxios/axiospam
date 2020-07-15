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
package axiospam

// PAMUser holds a PAM user and authentication results
type PAMUser struct {
	Username      string
	Password      string
	authenticated bool
	errorReason   error
}

// Authenticate takes the username and password and checks it with PAM
func (user *PAMUser) Authenticate() (result bool, err error) {
	result = false
	user.authenticated = false
	e := isUserLoginToken(user.Username, user.Password, true)
	user.errorReason = e
	if e != nil {
		return false, e
	}
	user.authenticated = true
	return true, nil
}

// IsAuthenticated will return the result of the user's authentication
func (user *PAMUser) IsAuthenticated() (result bool, reason error) {
	return user.authenticated, user.errorReason
}
