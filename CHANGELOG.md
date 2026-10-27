# Changelog

Earlier releases are described in their commit messages and pull requests; this file starts
with the first release that changes a public name.

## 0.9.0

### Changed

- Move to `ikigai-core` 0.2.0, the streams release (ledger #2261). Core types
  appear in the public API, so consumers must upgrade together; the old 0.1
  requirement excluded 0.2.0 under Cargo's 0.x rules.
- Update `ikigai-sign` to 0.4.0 and the development dependency `ikigai-sparql`
  to 0.3.0 so the entire dependency graph shares core 0.2.0.
- Update `ikigai-conformance` to 0.11.0, running DATATYPES and FAILURES by
  default. Require every check to run in both live and finished segment walks.

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
