[![GoDoc](https://godoc.org/github.com/mjwaxios/axiospam?status.svg)](https://godoc.org/github.com/mjwaxios/axiospam)
[![Go Report Card](https://goreportcard.com/badge/github.com/google/fscrypt)](https://goreportcard.com/report/github.com/mjwaxios/axiospam)
[![License](https://img.shields.io/badge/LICENSE-Apache2.0-ff69b4.svg)](http://www.apache.org/licenses/LICENSE-2.0.html)

[![Build Status](https://travis-ci.org/mjwaxios/axiospam.svg?branch=master)](https://travis-ci.org/mjwaxios/axiospam)
[![Coverage Status](https://coveralls.io/repos/github/mjwaxios/axiospam/badge.svg?branch=master)](https://coveralls.io/github/mjwaxios/axiospam?branch=master)

README for axiospam

make sure you have a axiospam file in /etc/pam.d

Note:
  the pam_unix module needs access to the /etc/passwd and /etc/shadow file,   if you run this Example
  as a user and not root, you can only validate your self.  Other methods like pam_sss don't have this
  issue.

See the go doc for this package for examples.

