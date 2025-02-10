# METADATA
# title: Confirmed Malicious
# description: |
#   Blocks if the package or author is tied to known malicious behavior
package policy.v1

import rego.v1

# METADATA
# title: Author is known malicious
deny contains issue if {
	some issue in data.issues
	issue.tag == "CA0001"
}

# METADATA
# title: Verified malware
deny contains issue if {
	some issue in data.issues
	issue.tag in {"CM0038", "CM1002"}
}

# METADATA
# title: Known-bad compiled binary
deny contains issue if {
	some issue in data.issues
	issue.tag == "CM0037"
}

# METADATA
# title: Depends on a known malicious package
deny contains issue if {
	some issue in data.issues
	issue.tag == "CM0039"
}
