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

# Returns a violation if the package contains minimal code and is unlikley worth the security risk
issue contains "Package contains minimal code" if {
   data.issue.tag == "IE0027"
}