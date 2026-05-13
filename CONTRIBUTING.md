# Contributing to A'ama

A'ama is in pre-alpha. The schema in `docs/architecture.md` is stable
enough to build against; everything else is open to change.

## Before opening an issue or PR

- **Discuss design changes first.** Open an issue describing the change
  before writing code, especially for anything that touches the schemas
  in `docs/architecture.md`. Schema changes ripple through every
  component.
- **Detectors don't go in this repo.** The public repo holds the
  framework, the schemas, and a handful of trivial example detectors.
  Real detector libraries live in private downstream repos and load via
  the `aama.detectors` entry point. If you want to contribute a
  detector, the question is usually "should this be in the framework or
  in your own plugin package?" — usually the latter.

## License

A'ama is AGPL-3.0-or-later. Contributions are accepted under the same
license. By submitting a PR, you confirm that you have the right to
contribute the code and agree to license it under AGPL-3.0-or-later.

## Code of conduct

Be civil. This is security tooling and the people who use it are
professionals; treat them like it.
