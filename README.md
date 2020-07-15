README for axiospam

make sure you have a axiospam file in /etc/pam.d

Note:
  the pam_unix module needs access to the /etc/passwd and /etc/shadow file,   if you run this Example
  as a user and not root, you can only validate your self.  Other methods like pam_sss don't have this
  issue.

See the go doc for this package for examples.

