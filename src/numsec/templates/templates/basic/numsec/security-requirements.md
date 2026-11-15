# Security requirements

> Requirements the implementation is checked against. Write them as testable
> statements; "be secure" is not a requirement.

## Authentication

- [ ] _Sessions expire after N hours of inactivity._
- [ ] _Credentials are stored with a memory-hard KDF (argon2id / scrypt / bcrypt)._

## Authorisation

- [ ] _Every endpoint that mutates state checks ownership, not just login._

## Input handling

- [ ] _All external input is validated server-side._
- [ ] _No user input reaches a shell, an SQL string or an eval()._

## Secrets

- [ ] _Secrets come from the environment or a secret manager._
- [ ] _No credential is ever committed; CI scans for them._

## Logging and data

- [ ] _No personal data or tokens in logs._
- [ ] _Deletion requests are honoured within N days._

## Assumptions and out of scope

- _e.g. the hosting provider secures the hypervisor._
- _e.g. physical access is out of scope._
