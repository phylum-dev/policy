# METADATA
# title: Typosquat
# description: |
#    Returns a violation if the package contains a potential typosquat with malicious characteristics
package policy.v1

import data.phylum.domain
import rego.v1

# Potential typosquat with malicious characteristics
deny contains typosquat_issue if {
	some dependency in data.dependencies

	some typosquat_issue in dependency.issues
	typosquat_issue.tag == "HM0008"

	count([d | dependency.issues[i].domain == domain.MALICIOUS; d := dependency.issues[i].domain]) > 1
}
