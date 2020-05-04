package restrictedtainttoleration

test_input_no_global_violation {
  input := { "review": input_review_global,
             "parameters": input_parameters_no_global }
  results := violation with input as input
  count(results) > 0
}

test_input_ok_global_pass {
  input := { "review": input_review_global,
             "parameters": input_parameters_ok_global }
  results := violation with input as input
  count(results) == 0
}

test_input_no_global_equals_match_pass {
  input := { "review": input_review_global_and_equals,
             "parameters": input_parameters_no_global }
  results := violation with input as input
  count(results) == 0
}

test_input_ok_global_equals_match_pass {
  input := { "review": input_review_global_and_equals,
             "parameters": input_parameters_ok_global }
  results := violation with input as input
  count(results) == 0
}

test_input_equal_match_pass {
  input := { "review": input_review_equal,
             "parameters": input_parameters_ok_global }
  results := violation with input as input
  count(results) == 0
}

test_input_equal_no_effect_match_pass {
  input := { "review": input_review_no_effect,
             "parameters": input_parameters_ok_global }
  results := violation with input as input
  count(results) == 0
}

test_input_equal_no_operator_match_pass {
  input := { "review": input_review_no_operator,
             "parameters": input_parameters_ok_global }
  results := violation with input as input
  count(results) == 0
}

test_input_equal_no_effect_no_operator_match_pass {
  input := { "review": input_review_no_effect_no_operator,
             "parameters": input_parameters_ok_global }
  results := violation with input as input
  count(results) == 0
}

test_input_equal_different_value_match_violation {
  input := { "review": input_review_different_value,
             "parameters": input_parameters_ok_global }
  results := violation with input as input
  count(results) == 0
}

test_input_no_toleration_field {
  input := { "review": input_review_different_value,
             "parameters": input_review_no_toleration_field }
  results := violation with input as input
  count(results) == 0
}

input_review_global = {
  "object": {
    "spec": {
      "tolerations": [
        {
          "operator": "Exists"
        }
      ]
    }
  }
}

input_review_global_and_equals = {
  "object": {
    "spec": {
      "tolerations": [
        {
          "operator": "Exists"
        },
        {
          "key": "taintname",
          "value": "taintvalue",
          "effect": "NoSchedule",
          "operator": "Equal"
        }
      ]
    }
  }
}

input_review_equal = {
  "object": {
    "spec": {
      "tolerations": [
        {
          "key": "taintname",
          "value": "taintvalue",
          "effect": "NoSchedule",
          "operator": "Equal"
        }
      ]
    }
  }
}

input_review_no_operator = {
  "object": {
    "spec": {
      "tolerations": [
        {
          "key": "taintname",
          "value": "taintvalue",
          "effect": "NoSchedule"
        }
      ]
    }
  }
}

input_review_no_effect = {
  "object": {
    "spec": {
      "tolerations": [
        {
          "key": "taintname",
          "value": "taintvalue",
          "operator": "Equal"
        }
      ]
    }
  }
}

input_review_no_effect_no_operator = {
  "object": {
    "spec": {
      "tolerations": [
        {
          "key": "taintname",
          "value": "taintvalue"
        }
      ]
    }
  }
}

input_review_different_value = {
  "object": {
    "spec": {
      "tolerations": [
        {
          "key": "taintname",
          "value": "wrongvalue",
          "operator": "Equal",
          "effect": "NoSchedule"
        }
      ]
    }
  }
}

input_review_exists = {
  "object": {
    "spec": {
      "tolerations": [
        {
          "key": "taintname",
          "effect": "NoSchedule",
          "operator": "Exists"
        }
      ]
    }
  }
}

input_review_no_toleration_field = {
  "object": {
    "spec": {}
  }
}

input_parameters_ok_global = {
  "restrictedTaint": {
     "key": "taintname",
     "value": "taintvalue",
     "effect": "NoSchedule"
  },
  "allowGlobalTolerationMatch": true
}

input_parameters_no_global = {
  "restrictedTaint": {
     "key": "taintname",
     "value": "taintvalue",
     "effect": "NoSchedule"
  },
  "allowGlobalTolerationMatch": false
}
