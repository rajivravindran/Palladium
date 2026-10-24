# Scope for the next implementation agent

This is a standalone Go policy library derived from Rajiv's supplied profile.go.
Read README.md and HANDOVER.md before integrating it. The Python Stage 0 project
is a separate component and has not been changed by this task.

- Keep policy evaluation deterministic and free of network or subprocess effects.
- Never derive trusted Context fields from external JSON, labels or model text.
- Only controller enrollment and authenticated normalization may establish identity.
- Scope every action by tenant, asset, runtime generation and current permissions.
- Keep shared-service containment separate from dedicated worker pause.
- Preserve the CLI's mandatory shadow mode and lack of trusted context.
- Do not add automatic resume or termination to this evaluator.
- An eligible candidate is not a performed action. Persist deduplication, refresh
  context, revalidate, call a fixed adapter, then verify the real outcome.
- Do not claim lexical path matching resolves symlinks, namespace aliases or inodes.
- Separate model input channels upstream; never treat an uncalibrated score as proof.
- Keep samples inert; no real credentials, private logs, model downloads or live
  attack endpoints in fixtures.
- Run gofmt, go test -race ./..., go vet ./... and the focused fuzz targets after
  changing path matching, JSON decoding, response eligibility or revalidation.
- Document actual checks and remaining integration obligations in HANDOVER.md.
