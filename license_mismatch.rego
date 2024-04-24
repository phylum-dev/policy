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

# Returns a violation if there is a license mismatch between metadata and files
issue contains "License mismatch" if {
   data.issue.tag == "IL0022"
}