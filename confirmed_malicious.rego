package policy

import rego.v1

# Returns a violation if the author is known malicious
# METADATA
# scope: rule
# schemas:
#   - data.issue: schema.issue
issue contains "Author has published malicious packages" if {
	data.issue.tag == "CA0001"
}

# Returns a violation if the package contains verified malware
issue contains "This package contains malware" if {
	data.issue.tag == "CM0038"
}

# Returns a violation if the package contains a known-bad compiled binary
issue contains "Contains known-bad compiled binary" if {
	data.issue.tag == "CM0037"
}

# Returns a violation if the package depends on a known malicious package
issue contains "This package depends on malware" if {
	data.issue.tag == "CM0039"
}
