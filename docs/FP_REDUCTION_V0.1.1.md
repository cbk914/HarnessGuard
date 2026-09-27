# v0.1.1 False Positive Reduction

HarnessGuard 0.1.1 stops treating every matching keyword in a large bundle as one behavioral chain.

High-impact static findings now require:
- local proximity;
- multiple strong signals;
- compatible source type;
- component-scoped corroboration.

`severity` represents possible impact. `confidence` represents evidence quality.

Examples intentionally suppressed or downgraded:
- authentication objects named `snapshot`;
- generic Undici `retry`, `fetch`, and `FormData` primitives;
- Chromium locale `.pak` strings;
- browser cache endpoints;
- session JWTs stored in user application state.

Full AST/data-flow analysis remains planned for a later release.
