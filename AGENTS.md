# AGENTS.md

agent-delivery-gates checks what an AI coding agent claims about a
change, not only whether the code it wrote runs. A test suite proves the
code executes. It does not prove a claim in a delivery report, such as
"the retry path is handled" or "the fix is verified," was ever actually
exercised. A green run and a false claim can read the same from outside.

This file exists so any agent working in this project, not only Claude
Code, can find and run the same checks a human reviewer would run.

## The commands

Every command below is a subcommand of the `agent-delivery-gates` binary
(short alias: `adg`). Each one is a plain program with a defined exit
code, and each can run on its own, from a shell, a CI step, or a git
pre-commit hook.

```
agent-delivery-gates validate-report [--report PATH] [--prior PATH] [--format text|json]
agent-delivery-gates test-diff [--rev REV] [--range A..B] [--staged] [--diff PATH] [--format text|json]
agent-delivery-gates mutate [--rev REV] [--range A..B] [--staged] [--paths PATH...] [--command CMD] [--max N] [--timeout SECONDS] [--format text|json]
agent-delivery-gates census [--base REF] [--command CMD] [--format text|json] [--format-in tap|junit] [--timeout SECONDS] [--no-rerun]
agent-delivery-gates induce [--dir PATH] [--spec PATH]... [--timeout SECONDS] [--format text|json]
agent-delivery-gates scan-prose [FILE...] [--rules PATH] [--require-rules] [--baseline PATH | --write-baseline PATH]
agent-delivery-gates tally [--tally PATH] [--format text|json] [--check]
agent-delivery-gates check
agent-delivery-gates init [--dry-run] [--force] [--prose-preset NAME] [--baseline] [--dir PATH]
```

### validate-report

Reads a delivery report and fails it when the report claims more than it
proved: a finding list missing a severity, a claim that a failure was
handled with no evidence a failure was ever induced, a missing commit
line before a claim that a step is finished.

Exit codes: `0` the report passes; `1` at least one check failed; `2` the
tool could not run as asked, an unreadable path, empty input, or a bad
argument.

### test-diff

Separates a diff into its source half and its test half, and reports
weakening signals found only in the test files: a removed assertion, a
removed test case, an added skip, a widened tolerance, a raised timeout.
A fix can reach a green run by changing the tests instead of the code
under test; this is how that move gets caught.

Exit codes: `0` no test file changed, or none of the changed files carry
a signal; `1` at least one signal was found; `2` could not run as asked,
including a git failure, so a broken git call never reads as a pass.

A test file can exist to hold text that only looks like a weakening, so
this check can be run against it. Such a file carries the line
`adg-test-diff: fixtures` inside a comment, a `//`, a `#`, or a `/* */`
one, within its first 20 lines, read from the file as it stands in the
working tree. The marker suppresses the signal checks for that one file.
It does not change classification: the file is still a test file, is
still counted in the test half, keeps its added and removed counts, and
no other file is affected. A marker past line 20, or one outside a
comment, is not honoured, so an exemption cannot be buried at the bottom
of a long file or written into a string.

The exemption lives in the file it affects and never in a list of paths
in a config file, so granting one appears in that commit's own diff where
a reviewer watches it happen. Every run names every file it skipped, in
the text report directly above the signal count and in the JSON as
`exemptFiles` with its own `exemptCount`, whether or not anything else
was found: a clean run that skipped two files does not read the same as a
clean run that skipped none.

Every pattern is tested against the line with its strings, its template
literals, its regular expressions, and any trailing comment blanked out,
so a detector word written inside a fixture string or inside a test's own
name is not read as a weakening. The line reported is always the original
one and never the blanked copy: a person reading a signal has to see the
real text.

That blanking reads one line at a time, so a string opened on an earlier
line is invisible to it. In

```
const xml = `
  <skipped type="pytest.skip"/>
`;
```

the middle line carries no quote of its own, so it reads as ordinary code
and its detector words still fire. A diff line is all this check ever
holds, so there is no whole file to read instead. For a test file where
this is common, the fixtures marker above is the answer.

### mutate

Breaks the code in a fixed set of known ways, one break at a time, runs
the test command after each one, and reports the breaks the command did
not notice. A break that nothing noticed means no test is holding that
line: the suite runs the code without proving it. The operators are
comparison boundaries, equality, boolean connectives, boolean literals,
and addition against subtraction.

It refuses to start on a dirty working tree, restores every file it
writes to, and checks the tree is clean again before it finishes; test
files are never mutated. A baseline run comes first, and a suite that is
already red is exit 2, not a result. `--staged` is the one narrowing of
the clean-tree rule: it mutates the staged diff, so a staged change is
its input, while an unstaged edit or an untracked file still stops it.

The limit with no fix: a SIGKILL, a power cut, or a hard crash cannot be
caught by any handler, and leaves the last mutated file mutated on disk.
Get a tracked file back with `git checkout -- <path>`. An untracked or
ignored path has no committed copy and no way back, which is why a
`--paths` target git ignores is refused before anything runs.

`--max N` attempts the first N mutations in path, then line, then column
order. A file early in that order can use the whole budget and a file
after it is never touched at all, so `0 survived` under a cap covers
only what was attempted. The report prints how many were planned and how
many attempted, and says plainly when the two differ.

Exit codes: `0` every attempted mutation got a verdict and none
survived; `1` at least one survived; `2` could not run as asked,
including a dirty tree, an unstaged change under `--staged`, a `--paths`
target git ignores, a failing baseline, no command to run, or a selector
that named nothing to mutate; `3` nothing survived, but at least one
mutation never got a verdict, so part of the run is unmeasured.

### census

Runs the test suite at a base commit and at HEAD, compares the two
censuses, and separately runs the test files this change touched against
the base source. It answers two questions a green run cannot: did a test
quietly stop running, and does a test added beside a fix actually fail
without the fix.

It reports a test that ran at the base commit and no longer runs
(`disappeared`), a suite that runs fewer tests than it did
(`count-dropped`), a test this change added that passes against the base
source and so demonstrates nothing about the change
(`not-red-before-green`), a test that went from pass to fail or back
(`flipped`), and a test this change added that could not run at all
against the base source (`errored-at-base`). That last one is an error,
not a failure: a test that never loaded proves nothing, and it is never
counted as red before green.

The working tree is never touched. The base commit is checked out with
`git worktree add --detach` into a temporary directory that is removed
afterwards, including when the run fails; `git checkout`, `git stash`,
and `git restore` are never run. It refuses to start on a dirty tree.

A fresh worktree has no `node_modules`. When package.json and every
lockfile are byte-identical between the base and HEAD, the main
worktree's install is reused through a symlink. When they differ, this
is exit 2: the base cannot be built comparably, and a base run that
fails to start must never read as every test disappearing.

That symlink points at your real install, not a copy of it. A suite that
writes into `node_modules` during the base run writes into the one your
own work uses and can corrupt it, and the end-of-run tree check cannot
see it happen: `node_modules` is gitignored, so nothing written inside it
shows up as a dirty tree. Point `--command` at a runner that does not
write there, or do not run this command over a suite that does.

Known limits, all of them real:

- Identity is the file plus the test name, so a renamed test reads as one
  test disappearing and another appearing. Two tests that share both
  halves share one identity, which happens whenever the runner names no
  file, as node's TAP does not for a passing test. A test added under a
  name another file already uses is then never checked against the base
  source, and the run reports an `identity-collision` it could not
  measure.
- Two to six full suite runs: HEAD, the base, this change's tests
  against the base source, and a re-run of any of those when a
  disagreement is re-checked. This belongs in pre-push, in CI, or in a
  Stop hook, never in a per-edit hook.
- A suite that disagrees with itself is reported, not smoothed over. When
  the two runs say different things about one test, in either direction,
  the result is `did-not-settle`: unmeasured, exit 3. It is not a finding,
  because the problem was not established, and it is not dropped, because
  its absence was not established either. A flaky suite therefore keeps
  producing exit 3 here until it is fixed.
- Only TAP and JUnit XML are read. A runner that writes JUnit XML to a
  file has to be told to print it instead.

Exit codes: `0` nothing found and everything was measured; `1` at least
one finding; `2` could not run as asked, including a dirty tree, a base
that cannot be resolved, a lockfile that differs between the base and
HEAD, or output in neither format; `3` nothing found, but part of the run
was unmeasured, such as a base run that could not be compared, a test
that errored against the base source, or a result the two runs did not
agree about.

### induce

Runs a declared failure injection twice: once with the handling in place,
where the check must pass, and once with the handling taken away, where
the same check must fail. A check that passes both ways is not measuring
the handling at all. It would pass if the feature produced nothing, which
is the one question `induced-failure-required` asks a reviewer to ask,
made mechanical. The rest of that record, whether the evidence exercises
the failure named and whether the check asserts a user-observable
outcome, is still a reviewer's judgement.

A spec is one JSON file per claim, in `.adg/induced/` by default:
`claim` (the sentence a report would make), `inject` (induce the failure
with the handling present, expected to pass), `neutralize` (induce the
same failure with the handling taken away, expected to fail), and
optionally `baseline` (the happy path, run first), `timeout` (seconds),
and `cwd`. Any other field is refused, and so is a spec with no
`neutralize`: the control is not optional, and a run without one proves
nothing.

A spec is a script, not data. Every command in it is handed to a shell
and runs with the privileges of whoever ran the command, on that machine,
against those files. Read a spec that came from a repository you did not
write before you run it, the way you would read any script before running
it. `cwd` is not contained to the repository, and containing it would buy
nothing: a command that can run at all can `cd` wherever it likes.

Specs share one working directory, run in filename order, and are not
isolated from each other, so a spec that leaves a file behind can change
the verdict of a spec that runs after it. A spec must clean up after
itself. The environment is inherited from the caller and is not cleaned:
if the variable a neutralize step sets to take the handling away is
already set in the caller's environment, the inject run is neutralized
too, and the spec reports `check-does-not-measure` against a handling
that works.

An entry in the spec directory that is not a `*.json` file is not read as
a spec, so `retry.JSON`, `retry.json.bak` and `retry.jsonc` are not run.
Every such entry is named and counted in the report header, so a
directory where only some specs ran cannot read like a clean run.

Verdicts: `proven` (inject passed, neutralize failed),
`handler-did-not-fire` (inject did not pass), `check-does-not-measure`
(both passed), and `could-not-run` (a command could not be executed, a
command was cut off before it could be judged, the baseline was already
failing, or the spec was malformed). The verdict lines say only what was
watched: two commands ran, one exited 0 and one did not.

On a proven spec it prints an evidence block naming the claim, both
commands, and the tail of what the neutralize command printed, which is
text a delivery report can cite: `validate-report` asks a robustness
claim to point at a commit, a path, or a command, and the inject command
is that command. Read that tail. Any neutralize failure counts, whatever
caused it, so a syntax error in the control script, a missing file, or a
runner that collected no tests all report `proven`; the printed output is
what lets a reader tell those from a control that worked.

It writes to no source file, so it needs no clean-tree gate and has none;
`git checkout`, `git stash`, and `git restore` are never run from it.

What it does not do:

- It does not read a delivery report, and `validate-report` does not run
  a spec. The two are separate checks on purpose.
- It does not know whether a spec describes the failure a report means.
- It cannot tell whether a spec is honest. A spec whose neutralize step
  breaks something unrelated still reports `proven`.
- It does not check why a neutralize command failed, only that it did.
- A command exiting 126 or 127 is read as never having run, because a
  neutralize step that was never runnable would otherwise look exactly
  like a control that worked. A command that chooses to exit 127 on its
  own is misread by that rule.
- A command killed by a signal, and a command that printed more than the
  64 MB this tool will hold, are each reported as themselves and never as
  a timeout. Both leave the step with no verdict.
- A command is killed at the timeout, but a process the command itself
  started can outlive it, so a timed-out spec is worth a look.

Exit codes: `0` every spec proven; `1` at least one spec not proven; `2`
could not run as asked, including no specs at all, a malformed spec, a
spec with no `neutralize`, a command that could not be executed, or a
failing baseline; `3` nothing failed, but at least one spec was cut off
and never measured, by the timeout, by a signal, or by printing more than
this tool will hold.

### scan-prose

Checks text against a configurable list of banned words and patterns.
With no rules file configured, nothing runs and the exit code is `0`;
point it at a rules file with `--rules`, or run `init --prose-preset
NAME`, to turn it on.

Exit codes: `0` clean, or nothing configured; `1` a banned pattern was
found; `2` the scan could not run: a missing rules file or a bad path.

What it needs: Node, the same as every other command here. It used to be
a bash script needing bash 4, which the bash 3.2 macOS ships as
`/bin/bash` could not run; it is a Node program now, so that whole
question is gone.

Every command here, and the pre-commit hook `init` writes, works as
shipped on macOS.

### Turning the prose scan on for an existing project

An existing project usually already has text the rules would catch, and
a scan that fails on everything already there gets turned off before it
catches anything new. Turn the rules on with `init --prose-preset NAME`,
then add `--baseline` to record every match the project already has, to
`.adg/prose-baseline.txt`. Once the baseline is in place, the scan fails
only on a new match; fixing an old one and deleting its recorded line
lets the baseline shrink over time.

### tally

Reads a log of what each gate has caught and reports its counts, or
checks the log for problems such as an entry pointing at a path nobody
can open.

Exit codes: `0` sound; `1` at least one problem; `2` could not run.

### check

Runs the checks a project should pass before a piece of work is
considered ready to hand off or to make public: no commit message
carries a personal path, no tracked file carries one
either, and the prose scan passes.

One check is off unless asked for: whether a commit message names the
tool that helped write it. That is a decision for the person making the
commit, so it runs only with `ADG_CHECK_AI_ATTRIBUTION=1` set, and it
reports `OFF` otherwise. `OFF` is not `SKIP`: a check nobody asked for
ran exactly as configured and leaves the verdict alone, while a check
that was meant to run and could not makes the whole run incomplete.

Exit codes: `0` everything passed; `1` at least one check failed, or was
skipped, which counts as incomplete; `2` could not run as asked.

Runs on bash 3.2 and BSD userland tools. One of its checks shells out to
the prose scan, which is a Node program, so all eight checks run on a Mac
with nothing installed beyond Node.

### init

Writes starter files into a project: a git pre-commit hook, this file,
and an empty gate tally log. The hook runs on bash 3.2 and BSD userland
tools, so it works under the bash macOS ships without anything installed
first. It only ever creates a file that does not
exist yet; nothing already on disk is changed unless `--force` is given.
Run `agent-delivery-gates init --help` for the full option list.

`init` also reports which languages it finds tracked with no tree-sitter
grammar resolvable yet, and, asked, fetches them into `.adg/grammars/`.
That directory is a fetch cache, not source: it gets its own `.gitignore`
the first time a fetch creates it, so do not `git add` anything inside it
by hand, and do not undo that ignore. A file there is checked against a
pinned digest every time it is actually loaded, not only when it is
fetched, so a stale or hand-placed one is refused, not trusted -- but
refused is still a broken gate for that language until it is fixed
with `npx adg lang add <language>`.

## Wiring into Claude Code

Two routes exist. The plugin route needs no manual wiring at all;
installing the plugin adds the hooks on its own. The standalone route
needs a few lines added to `.claude/settings.json` by hand;
`agent-delivery-gates init` prints them.

## What this does not cover

None of these commands read intent. A report can pass every check here
and still describe work that a human reviewer would reject on its own
merits. These checks catch a claim that outran its evidence; they do not
replace review.
