[![GoDoc](https://godoc.org/github.com/mjwaxios/axiospam?status.svg)](https://godoc.org/github.com/mjwaxios/axiospam)
[![Go Report Card](https://goreportcard.com/badge/github.com/mjwaxios/axiospam)](https://goreportcard.com/report/github.com/mjwaxios/axiospam)
[![License](https://img.shields.io/badge/LICENSE-Apache2.0-ff69b4.svg)](http://www.apache.org/licenses/LICENSE-2.0.html)

[![Build Status](https://travis-ci.org/mjwaxios/axiospam.svg?branch=master)](https://travis-ci.org/mjwaxios/axiospam)

README for Axios Pam Package

make sure you have a axiospam file in /etc/pam.d,  This package only uses pam auth, it will not use password, access, nor session modules.

```
$cat /etc/pam.d/axiospam 

#%PAM-1.0
# default for a centos system,
auth	   required	pam_sepermit.so
auth       substack     password-auth
auth       include      postlogin

# if we only want the local system use only this
#auth	required	pam_unix.so
```

Note:
  the pam_unix module needs access to the /etc/passwd and /etc/shadow file,   if you run this Example
  as a user and not root, you can only validate your self.  Other methods like pam_sss don't have this
  issue.

See the go doc for this package for examples from the code.

You will need to have libpam-devel installed to compile.

Example asking user for a username and password, then authenticating them.

```
package main

import (
	"fmt"

	"github.com/mjwaxios/axiospam"
	"github.com/mjwaxios/promptuser"
)

func main() {
	name := promptuser.Echo("Enter UserName: ")
	pass := promptuser.NoEcho("Enter Password: ")

	a, r := axiospam.Authenticate(name, pass)
	fmt.Printf("Person %s Authenticate result %v, reason %v\n", name, a.String(), r)

	pass2 := promptuser.NoEcho("Enter New Password: ")

	b, r2 := axiospam.ChangePassword(name, pass, pass2)
	fmt.Printf("Person %s change password result %v, reason %v\n", name, b.String(), r2)
}


```
