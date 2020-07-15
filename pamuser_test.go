package axiospam_test

import (
	"fmt"

	"github.com/mjwaxios/axiospam"
)

func Example() {
	p := axiospam.PAMUser{Username: "testana", Password: "thisisatest123"}
	p.Authenticate()
	auth, reason := p.IsAuthenticated()
	fmt.Printf("Person %s Authenticated: %v, Reason: %v\n", p.Username, auth, reason)
	// Output: Person testana Authenticated: true, Reason: <nil>
}
