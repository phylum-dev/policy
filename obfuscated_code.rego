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

# Returns a violation if the package contains obfuscated code
issue contains "Package contains obfuscated code" if {
   data.issue.tag in {"HM0029", "HM0099", "HM0023", "IM0040", "IM0041"}
}