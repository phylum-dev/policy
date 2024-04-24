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

# Returns a violation if the package appears to be a dependency confusion
issue contains "Package appears to be a dependency confusion" if {
   data.issue.tag == "HM0018"
}