---
description: Run all queued F6 prompts in prompts/queued/ in lex order
allowed-tools: Read, Write, Edit, Bash, Glob, Grep
---

You are running a chain of queued F6-style prompts. Each prompt is
self-contained (Goal / Architectural context / Critical invariants /
Touch 0 / Investigation / Touches / What NOT to do / Verify) and
expects to be executed end-to-end as its own unit of work.

## Process

1. Run `ls prompts/queued/*.md 2>/dev/null | sort` to enumerate the
   queue in lexicographic order. If the queue is empty, report
   "Queue empty — nothing to run" and stop.

2. For each file in the queue, in order:

   a. Read the file contents (`Read` tool, full file).

   b. Treat the file contents as the next prompt: execute its
      instructions completely. Run its Touch 0 first, walk through
      its investigation phase, execute each touch atomically per its
      commit cadence, and confirm its verify section passes before
      considering the prompt done.

   c. After the prompt completes cleanly, append a one-line summary
      to `logs/chain-summary.log` in this shape:
      `<ISO-8601 timestamp> <prompt-name> commits=<N> tests=<N> result=ok`

   d. Move the prompt file from `prompts/queued/` to `prompts/done/`
      using `mv` (preserves filename so the move is the completion
      signal).

3. **Halt-on-failure**: if any prompt fails (Touch 0 dirty-tree pause,
   verify-section assertion failure, genuine high-stakes Asked that
   can't auto-resolve), STOP. Log the failure to chain-summary.log
   with `result=failed reason=<one-line>`. Report which prompts
   completed and which are still queued. Do not proceed to subsequent
   queued prompts.

4. After the queue is empty (all prompts moved to done/), produce a
   final summary: total commits added, suite delta if available, any
   flags or notes worth surfacing.

## Discipline

- **Overnight-run authorization applies**: Asked questions with a
  clear (Recommended) option auto-resolve on the recommendation.
  Genuine high-stakes pauses (uncommitted prior work, content-loss
  risk, materially different design outcomes) still halt.
- **Atomic commits preserved** per F6 standard: feat → test → docs
  cadence, co-author lines, no squashing across prompts.
- **No push without explicit confirmation** — even after the chain
  completes, do not push.
- **Touch 0 of each prompt** runs against the state left by the prior
  prompt's commits. Tree should be clean (commits landed); a dirty
  tree at any Touch 0 is a halt-via-Asked condition, not a
  proceed-anyway.
