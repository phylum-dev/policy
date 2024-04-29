package policy

import data.phylum.domain

import rego.v1

# Returns `true` if the given dependency has a typosquat issue
has_typosquat if {
	some issue in data.dependency.issues
	issue.tag == "HM0008"
}

# Returns `true` if the dependency has more than one malware issue
has_more_than_one_malware_issue if {
	some issue in data.dependency.issues
	count([dom | issue.domain == domain.MALICIOUS; dom := issue.domain]) > 1
}

# METADATA
# scope: rule
# schemas:
#   - data.issue: schema.issue
issue contains "Potential typosquat with malicious characteristics" if {
	has_typosquat
	has_more_than_one_malware_issue
}
