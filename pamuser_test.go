package axiospam_test

import (
	"fmt"

	"github.com/mjwaxios/axiospam"
)

func Example() {
	p := axiospam.PAMUser{Username: "testana", Password: "thisisatest123"}
	auth, reason := p.IsAuthenticated()
	fmt.Printf("Person %s Authenticated: %v, Reason: %v\n", p.Username, auth, reason)
	p.Authenticate()
	auth, reason = p.IsAuthenticated()
	fmt.Printf("Person %s Authenticated: %v, Reason: %v\n", p.Username, auth, reason)
	// Output:
	// Person testana Authenticated: false, Reason: Authenticate not run yet
	// Person testana Authenticated: true, Reason: <nil>
}

func ExamplePAMUser() {
	p := axiospam.PAMUser{Username: "testana", Password: "thisisatest123"}
	if p.Username == "testana" && p.Password == "thisisatest123" {
		fmt.Print("User is Ok")
	}
	// Output:
	// User is Ok
}

func ExamplePAMUser_Authenticate() {
	p := axiospam.PAMUser{Username: "testana", Password: "thisisatest123"}
	auth, reason := p.Authenticate()
	fmt.Printf("Person %s Authenticated: %v, Reason: %v\n", p.Username, auth, reason)
	// Output:
	// Person testana Authenticated: true, Reason: <nil>
}

func ExamplePAMUser_IsAuthenticated() {
	p := axiospam.PAMUser{Username: "testana", Password: "thisisatest123"}
	p.Authenticate()
	auth, reason := p.IsAuthenticated()
	fmt.Printf("Person %s Authenticated: %v, Reason: %v\n", p.Username, auth, reason)
	// Output:
	// Person testana Authenticated: true, Reason: <nil>
}
