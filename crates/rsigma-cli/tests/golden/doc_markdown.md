# Whoami Execution

- **Status:** stable
- **Level:** medium

## Goal

Detects whoami execution, a common discovery step.

## Categorization

- attack.execution
- attack.t1059

## Strategy Abstract

Watch process creation for the whoami binary.

## Technical Context

Requires process_creation telemetry with CommandLine.

## Blind Spots and Assumptions

- Renamed whoami binaries evade the image match.
- Assumes CommandLine logging is enabled.

## False Positives

- Administrators enumerating their own privileges

## Validation

Run whoami in a lab and confirm the rule fires.

## Priority

**Level:** medium

Medium because discovery sits mid-kill-chain.

## Response

- Confirm the user and host.
- Correlate with other discovery activity.

