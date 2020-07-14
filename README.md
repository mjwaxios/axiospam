README for axiospam

make sure you have a axiospam file in /etc/pam.d

Note:
  the pam_unix module needs access to the /etc/passwd and /etc/shadow file,   if you run this Example
  as a user and not root, you can only validate your self.  Other methods like pam_sss don't have this
  issue.

Example to use this:

package main

import (
	"fmt"

	"github.com/mjwaxios/axiospam"
)


func main() {
    person := axiospam.PAMUser{Username: "testuser", Password: "thisisatestpassword"}
	axiospam.ValidateUser(&person)
	fmt.Printf("Person %s Authenticated: %v\n", person.Username, person.Authenticated)
}

