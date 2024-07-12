# METADATA
# title: Typosquat
# description: |
#    Blocks potential typosquat with malicious characteristics
package policy.v1

import data.phylum.domain
import rego.v1

# METADATA
# title: Potential typosquat with malicious characteristics
deny contains typosquat_issue if {
	some dependency in data.dependencies

	some typosquat_issue in dependency.issues
	typosquat_issue.tag == "HM0008"

	count([d | d := dependency.issues[_].domain; d == domain.MALICIOUS]) > 1
}
