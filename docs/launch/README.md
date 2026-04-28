# Launch runway

The harness is shipped. This directory is everything you need to put
it in front of strangers, in priority order. The work to ship is
*your* work — none of this gets results until somebody clicks
submit. Every minute spent polishing the README beyond this point
is a minute not spent finding the first user.

**Positioning** — capnagent is a *public purple-team harness for MCP
and AI-agent tool surfaces* (with a Rust capability-token engine
underneath). All four launch artifacts below lead with the corpus,
not the library — the corpus is the artifact, the library is the
engine.

**Current corpus state (as of 2026-04-28):**

- **10 purple-team rounds closed** (rounds 01–10). 6 hold-with-caveat;
  4 documented BREAKS, with fixes shipped (rounds 06, 08) or queued
  in v0.5 (rounds 07, 09, 10).
- **Angles run:** 4 parallel agents, 36 angles, **17 findings** —
  including **4 HIGH severity defects in our own engine** (sub-ulp
  f64 caveat-bypass, empty-attenuation brick, zero-byte audit key
  accepted, empty-caveat god-mode token).
- **v0.4 shipped** mid-corpus. **v0.5 SHIPPED 2026-04-28** — closes
  rounds 07/09/10 and 3 of the 4 HIGH angle findings (B.2
  empty-attenuation, B.3 zero-byte audit key, C.5 empty-caveat
  god-mode). The 4th HIGH (A.1 sub-ulp f64) remains under design
  discussion (units? integer-only mode? operator docs?).
- **Tests:** 242 Rust, 322 TS, criterion benches.

Lead every post with this. The drafts below were originally written
when the corpus had 1 round; they have been updated to lead with
the angles findings. The strongest sentence in any of them is:
*"We red-teamed our own engine in parallel and found 4 HIGH severity
defects — here they are, and here's the v0.5 fix queue."*

## Order of operations

| #  | Action                                               | Time     | Asset                |
|----|------------------------------------------------------|----------|----------------------|
| 1  | Show HN (try again — last one was blocked)           | 30 min   | `hn.md`              |
| 2  | Lobste.rs                                            | 15 min   | `lobsters.md`        |
| 3  | /r/rust                                              | 10 min   | `reddit.md`          |
| 4  | DM 5 specific people from Discord/LinkedIn           | 1 hour   | `outreach.md`        |
| 5  | /r/MachineLearning (different framing — see file)    | 10 min   | `reddit.md`          |
| 6  | (optional) X/Twitter thread linking the GitHub repo  | 20 min   | adapt `hn.md` body   |

Total time to push the launch: ~3 hours, spread over a week.

## What the assets are

- **`hn.md`** — title, body, comment-prep cheatsheet, failure-mode plan.
- **`lobsters.md`** — invite-only platform; lower volume but higher signal. Different framing than HN (more crypto/Rust specifics).
- **`reddit.md`** — three subs, three framings: /r/rust (technical decisions), /r/MachineLearning (threat model), /r/programming (skip unless you like flag wars).
- **`outreach.md`** — three cold-DM templates (founder, security engineer, MCP server maintainer) plus how to find the people to DM.

## What this directory does NOT contain

- A guarantee that any of this will land. Most launches fail. The point isn't to win; it's to get one round of real-world feedback so you know whether the project has gravity or not.
- More features. The library is done. Adding a 4th consumer or a fancier proptest will not change adoption.

## When you're done with this directory

If you've worked through 1–4 above and gotten zero traction, the right move is NOT to write more launch posts. It's to revisit positioning: Is the value prop wrong? Is the audience wrong? Is the elevator pitch unclear in 5 seconds?

If 1–4 produced any signal — a thoughtful comment, a real DM reply, an integration request — drop everything and run that thread to ground. Conversion is downstream of attention; attention is downstream of these six actions.
