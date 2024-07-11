# METADATA
# title: Obfuscated Code
# description: |
#    Returns a violation if the package contains obfuscated code
package policy.v1

import rego.v1

# Package contains obfuscated code
deny contains issue if {
	some issue in data.issues
	issue.tag in {"HM0029", "HM0099", "HM0023", "IM0040", "IM0041"}
}
