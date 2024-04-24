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

# Returns a violation if there is code execution on pacakge install
issue contains "Package contains code execution on install" if {
   data.issue.tag == "IM0042"
}

issue contains "Package contains code execution on install" if {
   data.issue.tag == "IM0043"
}

issue contains "Package contains code execution on install" if {
   data.issue.tag == "IM0044"
}