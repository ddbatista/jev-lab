# Jev-lab agent tool-call gate — P3 policy-layer seed.
#
# Architecture (from the prodsec-lab master plan + gateway research digest):
#   the gateway (here: policy/decide.py) calls the judge OUTSIDE OPA and
#   passes the typed decision IN as input. No http.send from Rego: it would
#   couple every eval to judge availability, cache stale verdicts, and turn
#   policy into an SSRF surface.
#
# Routing precedence, most-catastrophic-first — each rule cites its evidence:
#   1. force-block list          explicit human override (Stripe Radar pattern)
#   2. malformed input           unclassifiable = highest-risk band (fail-closed)
#   3. deny content signal       H7: all 10 hostile catches came from content
#                                checks (nouls / choice mass), zero from
#                                confidence bands. Checks act regardless of
#                                confidence.
#   4. force-allow list          overrides CAUTION routing (sandbox/gate), never
#                                a deny content signal. Audited.
#   5. sandbox content signal    same evidence as 3.
#   6. abstention                H4 item 5: noul ~0.5 is "cannot answer", not
#                                evidence. Absence of information -> human.
#                                (Without this rule the compositor failed open.)
#   7. judge unreachable         fail-closed checklist: human-gate, logged
#                                failure category, never silent allow.
#   8. low confidence            confidence's ONLY job: authorize acting
#                                without a human. Below the act band -> human.
#   9. dominant choice label     confident + no signals: route by the label.
#   10. else deny                default-deny catch-all.
#
# Per-provider bands (data.json): H7 measured that Jev's confidence separates
# clear from ambiguous (0.927 vs 0.414, AUROC 0.973) while Claude's does not
# (0.941 vs 0.690) and Claude leaked 3/5 ambiguous items to allow — so
# Claude's act_confidence sits above 1.0: its confidence alone can never
# authorize action, ambiguous always goes to a human.

package jevlab.gate

import rego.v1

# ------------------------------------------------------------------ helpers

# Thresholds for the judge's provider; undefined for unknown providers,
# which makes every threshold-gated rule below fail closed.
th := data.thresholds[input.judge.provider]

# Noul in [0.45, 0.55] carries no information (Day-1 item-5 finding).
# Information content of a noul is |value - 0.5|.
abstains(v) if {
	v >= 0.45
	v <= 0.55
}

known_provider if {
	input.judge.provider in object.keys(data.thresholds)
}

blocked if {
	input.tool_call.tool in data.force_block_tools
}

force_allowed if {
	input.tool_call.tool in data.force_allow_tools
}

# ------------------------------------------------------------- input health

malformed if not known_provider

malformed if {
	input.judge.available
	not input.judge.checks.touches_credentials
}

malformed if {
	input.judge.available
	not input.judge.checks.outside_repo
}

malformed if {
	input.judge.available
	not input.judge.verdict_probabilities
}

malformed if {
	input.judge.available
	not input.judge.confidence
}

judge_unavailable if not input.judge.available

# `error: null` means SUCCESS (no error) — a bare `input.judge.error` term
# would succeed on the defined-null value and mark every healthy judge
# unreachable. Caught by the offline replay, missed by fixtures that omitted
# the key entirely.
judge_unavailable if {
	input.judge.error != null
}

# ------------------------------------------------------------ content signals

cred_signal if {
	input.judge.available
	v := input.judge.checks.touches_credentials
	not abstains(v)
	v > th.cred_check
}

deny_signal if {
	input.judge.available
	input.judge.verdict_probabilities.deny > th.deny_prob
}

deny_signal if cred_signal

outside_signal if {
	input.judge.available
	v := input.judge.checks.outside_repo
	not abstains(v)
	v > th.outside_check
}

sandbox_signal if {
	input.judge.available
	input.judge.verdict_probabilities.sandbox > th.sandbox_prob
}

sandbox_signal if outside_signal

# judge.py flags abstentions; re-derive from raw values as belt-and-suspenders
# so a provider that stops reporting the flag still fails safe.
abstention if {
	input.judge.available
	input.judge.abstained[_]
}

abstention if {
	input.judge.available
	abstains(input.judge.checks.touches_credentials)
}

abstention if {
	input.judge.available
	abstains(input.judge.checks.outside_repo)
}

# --------------------------------------------------------------- confidence

# Confidence authorizes acting WITHOUT a human. High enough -> the choice
# label can route. Not high enough -> human review.
confident if {
	input.judge.available
	input.judge.confidence >= th.act_confidence
}

# Dominant choice label, deterministic tie-break toward the safer route.
winning(label) if {
	p := input.judge.verdict_probabilities[label]
	every q in input.judge.verdict_probabilities {
		q <= p
	}
}

choice_route := "deny" if winning("deny")
else := "gate" if winning("gate")
else := "sandbox" if winning("sandbox")
else := "allow" if winning("allow")

# -------------------------------------------------------------------- route

default route := "deny" # fail-closed catch-all

route := "deny" if blocked
else := "deny" if malformed
else := "deny" if deny_signal
else := "allow" if force_allowed # beats caution, never a deny signal
else := "sandbox" if sandbox_signal
else := "gate" if abstention
else := "gate" if judge_unavailable
else := "gate" if not confident
else := choice_route
# (no final else needed: `default route := "deny"` is the fail-closed catch-all)

# ------------------------------------------------------------------ reasons

reasons contains "force_block" if blocked

reasons contains "malformed_input_fail_closed" if malformed

reasons contains "deny_signal:verdict_choice" if {
	input.judge.available
	input.judge.verdict_probabilities.deny > th.deny_prob
}

reasons contains "deny_signal:touches_credentials" if cred_signal

reasons contains "force_allow_override_audited" if force_allowed

reasons contains "sandbox_signal:outside_repo" if outside_signal

reasons contains "sandbox_signal:verdict_choice" if {
	input.judge.available
	input.judge.verdict_probabilities.sandbox > th.sandbox_prob
}

reasons contains "abstention:no_information_human_review" if abstention

reasons contains "judge_unavailable:fail_closed_gate" if judge_unavailable

reasons contains "below_act_confidence:human_review" if {
	input.judge.available
	not confident
	not abstention
	not judge_unavailable
}

reasons contains "confident_choice_label" if {
	route == choice_route
	not deny_signal
	not sandbox_signal
	not abstention
	not judge_unavailable
}

reasons contains "default_deny:unclassifiable" if {
	route == "deny"
	not blocked
	not malformed
	not deny_signal
}

# ----------------------------------------------------------------- decision

decision := {
	"route": route,
	"allowed": route == "allow",
	"reasons": reasons,
	"policy_version": data.policy_version,
	"provider": input.judge.provider,
	"model": object.get(input.judge, "model", null),
	"confidence": object.get(input.judge, "confidence", null),
	"checks": object.get(input.judge, "checks", {}),
	"abstained": object.get(input.judge, "abstained", []),
	"tool": input.tool_call.tool,
	"thresholds_applied": object.get(data.thresholds, input.judge.provider, null),
}
