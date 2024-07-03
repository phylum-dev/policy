# METADATA
# title: Confirmed Malicious
# description: |
#   Return a violation if the pacakge or author is tied to known malicious behavior

package policy.v1

import rego.v1

# Returns a violation if the author is known malicious
deny contains issue if {
   some issue in data.issues
   issue.tag == "CA0001"
}

# Returns a violation if the package contains verified malware
deny contains issue if {
   some issue in data.issues
   issue.tag == "CM0037"
}

# Returns a violation if the package contains a known-bad compiled binary
deny contains issue if {
   some issue in data.issues
   issue.tag == "CM0038"
}

# Returns a violation if the package depends on a known malicious package
deny contains issue if {
   some issue in data.issues
   issue.tag == "CM0039"
}
