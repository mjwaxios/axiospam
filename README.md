[![GoDoc](https://godoc.org/github.com/mjwaxios/axiospam?status.svg)](https://godoc.org/github.com/mjwaxios/axiospam)
[![Go Report Card](https://goreportcard.com/badge/github.com/google/fscrypt)](https://goreportcard.com/report/github.com/mjwaxios/axiospam)
[![License](https://img.shields.io/badge/LICENSE-Apache2.0-ff69b4.svg)](http://www.apache.org/licenses/LICENSE-2.0.html)

README for axiospam

make sure you have a axiospam file in /etc/pam.d

Note:
  the pam_unix module needs access to the /etc/passwd and /etc/shadow file,   if you run this Example
  as a user and not root, you can only validate your self.  Other methods like pam_sss don't have this
  issue.

See the go doc for this package for examples from the code.

Example asking user for a username and password, then authenticating them.

```
package main

import (
	"fmt"

	"github.com/mjwaxios/axiospam"
	"github.com/mjwaxios/promptuser"
)

func main() {
	user := promptuser.Echo("Enter UserName: ")
	pass := promptuser.NoEcho("Enter Password: ")
	p := axiospam.New(user, pass)

	if a, r := p.Authenticate(); a {
		fmt.Printf("Person %s is Authenticated\n", p.Username)
	} else {
		fmt.Printf("Persion %s failed to Authenticate because %v", p.Username, r)
	}
}

```
