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
	p := axiospam.New("testana", "thisisatest123")
	auth, reason := p.IsAuthenticated()
	fmt.Printf("Person %s Authenticated: %v, Reason: %v\n", p.Username, auth, reason)
	p.Authenticate()
	auth, reason = p.IsAuthenticated()
	//	fmt.Printf("Person %s Authenticated: %v, Reason: %v\n", p.Username, auth, reason)
	p.SetPassword("BadPass")
	auth, reason = p.Authenticate()
	fmt.Printf("Person %s Authenticated: %v, Reason: %v\n", p.Username, auth, reason)
	//	// Person testana Authenticated: true, Reason: <nil>
	// Output:
	// Person testana Authenticated: false, Reason: Authenticate not run yet
	// Person testana Authenticated: false, Reason: incorrect login passphrase
}

func ExamplePAMUser() {
	axiospam.New("testana", "thisisatest123")
	// Output:
}

func ExamplePAMUser_Authenticate() {
	p := axiospam.New("testana", "thisisatest123")
	auth, reason := p.Authenticate()
	fmt.Printf("Person %s Authenticated: %v, Reason: %v\n", p.Username, auth, reason)
	// Output:
	// Person testana Authenticated: false, Reason: incorrect login passphrase
}

func ExamplePAMUser_IsAuthenticated() {
	p := axiospam.New("testana", "thisisatest123")
	p.Authenticate()
	auth, reason := p.IsAuthenticated()
	fmt.Printf("Person %s Authenticated: %v, Reason: %v\n", p.Username, auth, reason)
	// Output:
	// Person testana Authenticated: false, Reason: incorrect login passphrase
}
