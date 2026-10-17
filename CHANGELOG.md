# Changelog

Earlier releases are described in their commit messages and pull requests; this file starts
with the first release that changes a public name.

## 0.8.0

A **breaking** change under 0.x, so a minor bump: anything that matches on an endpoint id, a
catalog label or an MCP tool name derived from one must move with it.

### Renamed

Every endpoint id now follows the naming convention `ikigai-core` states: a short `kebab-case`
noun, the bound IRI's own segment plus the module's prefix. The IRIs already conformed and do
not change, so nothing that resolves `urn:log:*` is affected. An id is not an IRI, so there is
no alias: the old ids are gone, not deprecated.

| old id | new id | IRI (unchanged) |
| --- | --- | --- |
| `logWrite` | `log-write` | `urn:log:write` |
| `logConfig` | `log-config` | `urn:log:config` |
| `logSegments` | `log-segments` | `urn:log:segments` |
| `logSegment` | `log-segment` | `urn:log:{segment}` |
| `logTransrept` | `log-transrept` | `urn:log:transrept` |
| `logVerify` | `log-verify` | `urn:log:verify` |

The conformance test no longer skips `NAMES`: every check runs.
