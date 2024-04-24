package policy

import data.phylum.domain
import data.phylum.level
import future.keywords.contains
import future.keywords.if
import future.keywords.in


# METADATA
# scope: rule
# schemas:
#   - data.issue: schema.issue

# Returns a violation if there is suspicious code execution on pacakge install
issue contains "Package contains suspicious code execution on install" if {
   data.issue.tag == "CM0007"
}

issue contains "Package contains suspicious code execution on install" if {
	endswith(data.issue.tag, "M0031")
}