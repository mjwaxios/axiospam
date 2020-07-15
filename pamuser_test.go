/*
 * pamuser_test.go - The Example code for go doc
 *
 * Copyright 2020 Michael Wyrick
 * Author: Michael Wyrick
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
 */package axiospam_test

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
