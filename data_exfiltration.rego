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

# Returns a violation if the package contains common data exfiltration techniques
issue contains "Package contains environment variable enumeration" if {
   data.issue.tag == "HM0025"
}

issue contains "Package contains webhook exfiltration" if {
   data.issue.tag == "HM0036"
}