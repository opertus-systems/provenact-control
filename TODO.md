# TODO

Last updated: 2026-03-16

## Priority

- Revisit `#26` (`axum 0.8.8`) and fix the failing `rust` job before merging.
- Keep enforcing bounded JSON parsing and CI action pinning across new endpoints and workflow edits.
- Add explicit regression coverage for any future request-body parsing or OpenAPI sync changes.

## Notes

- The recent audit pass merged the JSON decoding and CI hardening work.
