# Architecture

> Keep this short and factual: components, data flows, integrations. The assistant
> uses it to reason about where threats actually land.

## Components

| Component | Responsibility | Trust level |
| --- | --- | --- |
| _web app_ | _..._ | public |
| _worker_ | _..._ | internal |

## Data flows

1. _Client sends X to Y over HTTPS._
2. _Y validates, then writes to Z._
3. _..._

## External integrations

| Service | Direction | Credentials | Notes |
| --- | --- | --- | --- |
| _e.g. payment provider_ | outbound | API key from secret manager | webhooks verified |

## Deployment

- _Runtime, regions, who can reach what, which ports are public._

## Known weak spots

- _Anything you already know is shaky. Being honest here makes the analysis useful._
