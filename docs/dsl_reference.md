# ComplianceBot DSL Reference

## Overview
The ComplianceBot Domain Specific Language (DSL) is a strongly-typed, declarative language for defining compliance policies.

## File Structure
Files must end in `.dsl` and follow this structure:

```groovy
policy POLICY_ID {
 version: "1.0.0"
 name: "Policy Name"
 description: "Optional description"
 effective_date: "YYYY-MM-DD" // Optional
 supersedes: "PREV_VERSION" // Optional

 control ControlName {
 signals: [ signal.name, other.signal ]
 }

 rules {
 // Logic goes here
 }

 compliance {
 STANDARD_NAME: "Clause Ref"
 }
}
```

## Keywords

### Metadata
- `policy`: Defines the policy block. ID should be alphanumeric (e.g., `SEC_PR_001`).
- `version`: SemVer string (e.g., `1.0.0`).
- `name`: Human-readable title.
- `effective_date`: Date when policy becomes active.
- `supersedes`: ID or Version this policy replaces.

### Logic
- `control`: Defines which signals are required.
- `signals`: List of dot-notation signal names.
- `require`: Inverse logic. `require x > 1` means `when x <= 1 enforce BLOCK`.
- `when`: conditional block.
- `enforce`: Action to take (`BLOCK`, `WARN`, `COMPLIANT`).
- `message`: Failure message shown to user.

### Operators
- Comparison: `==`, `!=`, `>`, `>=`, `<`, `<=`
- Set: `in`, `not in`
- Logical: `and` (OR is not supported in `require` block, use multiple rules).

## Data Types
The DSL interacts with **Signals**, which are primitives:
- `bool`: `true`, `false`
- `string`: "text"
- `int`/`float`: 10, 4.5
- `list`: ["a", "b"]

## Example
```groovy
policy EXAMPLE_001 {
 version: "1.0.0"
 name: "Example"
 
 control Basic {
 signals: [ approvals.count ]
 }

 rules {
 require approvals.count >= 2
 }
}
```
