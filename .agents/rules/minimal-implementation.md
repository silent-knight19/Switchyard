---
trigger: always_on
description: "Apply minimal, secure, production-quality implementation standards to every Switchyard coding task."
---

# Switchyard — Minimal Implementation Rule

## Applicability

Apply this rule to every relevant coding, debugging, refactoring, configuration, testing, and code-review task in the Switchyard workspace.

## Core Principle

Produce the smallest correct, readable, secure, maintainable implementation that satisfies the authorized task specification.

Optimize for minimum necessary complexity, not an arbitrary number of lines.

## Mandatory Engineering Rules

1. Implement only explicitly authorized requirements.
2. Prefer the smallest reasonable change set.
3. Reuse existing code and platform capabilities before introducing new components.
4. Avoid speculative features, premature optimization, and unnecessary generalization.
5. Do not create unnecessary helpers, wrappers, interfaces, factories, classes, or abstraction layers.
6. Do not introduce dependencies unless required and justified.
7. Avoid boilerplate, placeholder implementations, and redundant configuration.
8. Avoid comments that merely repeat what the code already communicates.
9. Avoid duplicate validation, excessive logging, and unnecessary error wrapping.
10. Do not create additional files when existing files can appropriately satisfy the requirement.
11. Prefer straightforward, idiomatic code over unnecessarily elaborate design patterns.
12. Never compromise security, tenant isolation, correctness, reliability, readability, concurrency safety, or required test coverage to reduce code size.
13. Preserve architectural boundaries and established API contracts.
14. Do not modify unrelated files or perform opportunistic refactoring.
15. Before completing a task, inspect the final diff and remove unnecessary code, dependencies, abstractions, and configuration introduced by that task.

## Architecture and Authorization

- Architecture v1.2 remains authoritative.
- Follow the repository's "AGENTS.md" and the authorized atomic task specification.
- Do not introduce architectural deviations without explicit project-owner approval.
- Do not implement dependent tasks before their prerequisites are accepted.
- Report ambiguities and conflicts rather than inventing requirements.

## Verification

Before reporting task completion:

1. Verify every applicable acceptance criterion.
2. Execute the tests and checks required by the authorized task.
3. Review the diff for unnecessary complexity.
4. Explain any newly introduced dependency or significant abstraction.
5. Report files changed, verification results, and outstanding concerns.

## Prohibited Behavior

- Unrequested feature expansion.
- Speculative infrastructure.
- Unnecessary frameworks.
- Excessive scaffolding.
- Unjustified abstractions.
- Placeholder code presented as completed functionality.
- Removing required security checks or tests to reduce line count.
- Automatically proceeding to the next atomic task.
