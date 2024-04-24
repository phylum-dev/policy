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

# Returns a violation if the package contains secrets/tokens excluding test/example files
issue contains "Secrets in non-test file" if {
   data.issue.tag == "ME0016"
}