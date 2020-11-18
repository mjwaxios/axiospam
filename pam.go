/*
 * pam.go - Utility functions for interfacing with the PAM libraries.
 *
 * Modified: 2020 by Michael Wyrick
 *
 * Copyright 2017 Google Inc.
 * Author: Joe Richey (joerichey@google.com)
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

package axiospam

/*
#cgo LDFLAGS: -lpam
#include "pam.h"

#include <pwd.h>
#include <stdlib.h>
#include <security/pam_modules.h>
*/
import "C"
import (
	"errors"
	"os/user"
	"unsafe"
)

// Handle wraps the C pam_handle_t type. This is used from within modules.
type handle struct {
	handle *C.pam_handle_t
	status C.int
	// PamUser is the user for whom the PAM module is running.
	PamUser *user.User
}

func (h *handle) err() error {
	if h.status == C.PAM_SUCCESS {
		return nil
	}
	s := C.GoString(C.pam_strerror(h.handle, C.int(h.status)))
	return errors.New(s)
}

// Transaction represents a wrapped pam_handle_t type created with pam_start
// form an application.
type transaction handle

// Start initializes a pam Transaction. End() should be called after the
// Transaction is no longer needed.
func start(service, username string) (*transaction, error) {
	cService := C.CString(service)
	defer C.free(unsafe.Pointer(cService))
	cUsername := C.CString(username)
	defer C.free(unsafe.Pointer(cUsername))

	t := &transaction{
		handle: nil,
		status: C.PAM_SUCCESS,
	}
	t.status = C.pam_start(
		cService,
		cUsername,
		C.goConv,
		&t.handle)
	return t, (*handle)(t).err()
}

// End finalizes a pam Transaction with pam_end().
func (t *transaction) End() {
	C.pam_end(t.handle, t.status)
}

// authenticate returns a boolean indicating if the user authenticated correctly
// or not. If the authentication check did not complete, an error is returned.
func (t *transaction) authenticate(quiet bool) (bool, error) {
	var flags C.int = C.PAM_DISALLOW_NULL_AUTHTOK
	if quiet {
		flags |= C.PAM_SILENT
	}
	t.status = C.pam_authenticate(t.handle, flags)
	if t.status == C.PAM_AUTH_ERR {
		return false, nil
	}
	return true, (*handle)(t).err()
}

// changeTok changes the user password
func (t *transaction) changeTok(quiet bool) (int, error) {
	var flags C.int = C.PAM_DISALLOW_NULL_AUTHTOK
	if quiet {
		flags |= C.PAM_SILENT
	}
	
	t.status = C.pam_chauthtok(t.handle, flags)

	switch t.status {
	case C.PAM_SUCCESS:
		return 0, nil
	case C.PAM_AUTHTOK_ERR:
		return 20, nil
	}

	return -1, (*handle)(t).err()
}

func (t *transaction) accountManagement(quiet bool) (int, error) {
	var flags C.int
	if quiet {
		flags |= C.PAM_SILENT
	}
	t.status = C.pam_acct_mgmt(t.handle, flags)

	return int(t.status), nil
}
