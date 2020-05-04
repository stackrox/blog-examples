# Open Policy Agent (OPA) Gatekeeper Taint Tolerations Policy

This is a functional OPA Gatekeeper constraint policy for enforcing allowed
taint tolerations in pods.

Please see the original blog post at []() for more information on writing
and testing OPA Gatekeeper constraint policies.

## Basic Usage

This policy was tested against Gatekeeper release[3.1.0-beta.8](https://github.com/open-policy-agent/gatekeeper/releases/tag/v3.1.0-beta.8)

1. [Deploy OPA Gatekeeper](https://github.com/open-policy-agent/gatekeeper) in
your Kubernetes cluster.
1. Apply the `ConstraintTemplate`: `kubectl apply -f constraint_template.yaml`
1. Apply the sample constraint: `kubectl apply -f constrant.yaml`
1. Apply a deployment with the forbidden taint and watch it fail: `kubectl apply -f hello-world.yaml`
