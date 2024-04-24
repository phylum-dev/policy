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

# Returns a violation if there is code execution on package install
issue contains "Package contains code execution on install" if {
   data.issue.tag in {"IM0042", "IM0043", "IM0044"}
}