# {{project_name}}

> Filled in by a human, read by the assistant before every threat-modeling session.

## What this project does

_TODO: one paragraph, no marketing. What problem does it solve and for whom?_

## Data it handles

| Data | Classification | Where it lives | Retention |
| --- | --- | --- | --- |
| _e.g. user email_ | personal | Postgres `users` | until account deletion |

## Trust boundaries

- _e.g. browser → public API (untrusted input)_
- _e.g. API → internal worker queue (trusted network)_

## Users and roles

| Role | Can do | Cannot do |
| --- | --- | --- |
| anonymous | _..._ | _..._ |
| authenticated user | _..._ | _..._ |
| admin | _..._ | _..._ |

## Non-goals

- _What this project deliberately does not protect against._
