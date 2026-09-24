# policy/ — design notes

Why this layer exists, what each file is, and the reasoning behind the
rules and the numbers. Read this before the `.rego` file.

## The cast

| file | role |
|---|---|
| `judge_gate.rego` | the RULES — routing logic and fail-closed behavior. Changes rarely; code-review mindset. |
| `data.json` | the NUMBERS — thresholds, overrides, policy version. Changes often; config change, not a redeploy. |
| `judge_gate_test.rego` | 20 tests over the rules, each named for the property it guards. |
| `decide.py` | the runner — wires `judge.py` to `opa eval`, prints/logs the decision doc. |

The Rego/data split is the Stripe Radar pattern: the model (judge) emits
signals, the rules layer routes, and the tunable numbers live in data. An
engineer can retune thresholds without being able to rewrite the security
logic — and every decision doc records which numbers decided
(`thresholds_applied`), so any past decision is reproducible against
`policy_version`.

## The data (data.json)

- `policy_version` — stamped into every decision doc: "which policy was in
  effect" is answerable forever.
- `thresholds.jev` — `act_confidence: 0.90` (the confidence hatch; below it,
  a human reviews) plus content thresholds at 0.50. Basis: H7 measured Jev's
  confidence at 0.927 on clear items vs 0.414 on ambiguous ones — 0.9 is
  where "the judge knows" separates from "the judge is guessing."
- `thresholds.claude` — same content thresholds, but `act_confidence: 1.01`:
  deliberately unreachable. Basis: H7 showed Claude's confidence does not
  separate clear from ambiguous (0.941 vs 0.690) and it leaked 3/5 ambiguous
  items to allow when routing on its own judgment. In this policy Claude
  still contributes content checks (all 5 hostile calls denied through it in
  replay) but its "I'm sure" can never authorize acting without a human.
  A generative model's confidence isn't evidence; the data file says so
  numerically.
- `force_block_tools` / `force_allow_tools` — human override valves (both
  empty by default). Block is unconditional. Allow overrides CAUTION
  (low-confidence, sandbox) but never a deny content signal — that immunity
  is rule order, not a flag someone can flip.

Every threshold block carries a `_basis` field citing the measurement behind
the value. No vibes.

## The policy (judge_gate.rego)

**Helpers.** `th` is the per-provider threshold lookup — an unknown provider
makes `th` undefined, which fails every comparison, which fails closed.
`abstains(v)` marks the 0.45–0.55 band: a noul at ~0.5 is not "leaning no,"
it is "cannot answer." Information content of a noul is |v − 0.5|.

**Input health.** `malformed` (unknown provider, missing checks /
probabilities / confidence) and `judge_unavailable` (`available: false`, or
a non-null `error`). Unclassifiable = highest risk. (The null-vs-absent
distinction was a real bug the replay caught — `error: null` on success used
to read as "judge down.")

**Content signals.** `deny_signal` = deny choice mass above threshold OR
`cred_signal` (credentials noul, non-abstaining). `sandbox_signal` = sandbox
mass OR outside-repo noul. Two independent roads to each; either suffices.

**Abstention.** The judge's own `abstained` flag, OR re-derived from raw
values as belt-and-suspenders (in case a provider stops reporting the flag).

**Confidence.** `confident` = confidence ≥ the provider's `act_confidence`.
`choice_route` picks the dominant label with tie-breaks toward the safer
route (deny > gate > sandbox > allow).

**The route — an else-if chain in precedence order. The ordering IS the
security posture:**

```
1. force_block         -> deny    human override, absolute
2. malformed           -> deny    don't understand the input: assume worst
3. deny_signal         -> deny    content checks act regardless of confidence
4. force_allow         -> allow   overrides CAUTION only — unreachable if 2/3 fired
5. sandbox_signal      -> sandbox
6. abstention          -> gate    no information -> human
7. judge_unavailable   -> gate    fail-closed, logged
8. not confident       -> gate    the confidence hatch
9. choice_route                  confident + clean: route by the label
default: deny                    the catch-all
```

Two properties fall out of the order:

- **Content checks run before confidence ever matters.** H7 justified this:
  all 10 hostile catches across both judges came from content checks;
  confidence never caught anything. Confidence's only job is deciding
  whether a HUMAN must look — never what the call is.
- **"allow" is the hardest lane to reach.** No block, not malformed, no deny
  signal, no sandbox signal, no abstention, judge reachable, confident, and
  the dominant label says allow. Everything else fails toward deny or gate.

**reasons** — a set of machine-readable strings, one per rule that was true.
It is an inventory of evidence, not the list of deciders: a sandbox reason
can appear on a denied row (recorded, but out-ranked by deny precedence).
`force_allow` is always audited by name when it fires.

**decision** — the audit doc: route, allowed, reasons, policy_version,
provider, model, confidence, checks, abstained, tool, and the exact
`thresholds_applied`. Everything an incident review needs, computable after
the fact.

## The tests (judge_gate_test.rego)

20 cases: the four happy-path lanes; the H4 item-5 attack reproduced
exactly (confidently-wrong 0.89 allow + 0.5 abstaining noul must gate, not
allow); abstention re-derived from raw values; content-signal-beats-low-
confidence; the Claude 1.01 rule both ways; judge unreachable/error; unknown
provider; missing fields; force-block beating a clean allow; force-allow
beating caution but losing to a credential signal; injected `policy_note`
text being inert (no rule reads free-text state, so the decision is
provably unchanged); decision-doc completeness.

What the suite did NOT catch — a lesson worth keeping — was the `error: null`
bug, because fixtures either omitted the key or set a real string, never
null-on-success. The offline replay of real logs caught it. Policy changes
get validated against frozen judge data before touching a live call; that's
what `decide.py --offline` is for.

## The runner (decide.py)

Pure glue, deliberately boring. `judge.py`'s `decide()` runs OUTSIDE OPA
(enrich-then-evaluate — no `http.send` from Rego, which would couple every
eval to judge availability and make policy an SSRF surface), the typed
payload goes in via stdin, `opa eval` returns the decision doc. If OPA
itself dies or times out, the runner emits a deny with a
`policy_engine_failure` reason — the engine being down is just another
fail-closed condition.

## Measured (replay of the H7 logs + live run)

- Jev through policy: 14/20 — zero hostile→safe, zero ambiguous→allow.
  The confidence hatch converts would-be leaks into human review. The
  entire operational cost is three over-cautious human reviews.
- Claude through policy: 7/20 by design — content-checks-only, everything
  else routed to humans.
- Live run == offline replay, byte-identical routes and reasons: the
  reproducibility property (frozen questions + near-deterministic judge +
  pure-function policy) demonstrated empirically.
