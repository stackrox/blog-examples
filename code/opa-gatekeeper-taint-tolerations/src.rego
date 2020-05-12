package restrictedtainttoleration

# Global assignments
pod := input.review.object
tolerations := pod.spec.tolerations
taint := input.parameters.restrictedTaint

# This comprehension creates an array with an entry for
# each matching toleration in the tolerations array
matching_tolerations := [match | match := toleration_match(tolerations[_])]

# A toleration with no key matches all taints
global_tolerations := [key | k := object.get(tolerations[_], "key", "")
                             k == ""
                             key := k]

default allow_global = false
allow_global {
  input.parameters.allowGlobalToleration == true
}

# Fail if matching toleration exists
violation[{"msg": msg}] {
  count(global_tolerations) == 0
  count(matching_tolerations) > 0
  msg := sprintf("Toleration is not allowed for taint %v", [taint])
}

# Fail if global toleration exists and we disallow global tolerations for
# this taint
violation[{"msg": msg}] {
  count(global_tolerations) > 0
  not allow_global
  msg := sprintf("Global tolerations not allowed for taint %v", [taint])
}

# Functions to test if pod toleration matches the taint
toleration_match(toleration) {
  key := object.get(toleration, "key", "")
  key == taint.key
  effect := object.get(toleration, "effect", "")
  effect_check(effect)
  operator := object.get(toleration, "operator", "Equal")
  operator_check(toleration, operator)
}

# Functions can be defined multiple times, matching against non-variable args
# This acts as a conditional

# If effect is empty, match any
effect_check("") {
  true
}

# Otherwise, specific effect must match
effect_check(effect) {
  effect == taint.effect
}

# When the toleration operator is "Equal" we need to match value fields
operator_check(toleration, "Equal") {
  value := object.get(toleration, "value", "")
  value == taint.value
}

# When the toleration operator is "Exists", the match is always true
# because we already matched on key and effect
operator_check(toleration, "Exists") {
  true
}

