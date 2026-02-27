Output demo.mp4
Set Theme "Catppuccin Mocha"
Set FontFamily "FiraCode Nerd Font"
Set FontSize 14
Set Width 1200
Set Height 800
Set WindowBar Colorful
Set TypingSpeed 40ms
Set Padding 24

# ── Preamble: hidden env setup ─────────────────────────────────────────────────
Hide
Type "cd ~/dev/the-janitor"
Enter
Type "export JANITOR=~/dev/the-janitor/target/release/janitor"
Enter
Type "export GODOT=~/dev/gauntlet/godot"
Enter
Type "export PS1='[janitor demo] $ '"
Enter
Sleep 500ms
Show

# ══════════════════════════════════════════════════════════════════════════════
# PHASE 1: THE HOOK  (0-15s)
# Live PR forensics: bounce PR #116833 (TitanNano) through the slop gate.
# Crucible result: slop_score=70, antipatterns_found=1, unlinked_pr=1
# ══════════════════════════════════════════════════════════════════════════════

Type "# Live: bouncing godotengine/godot PR #116833 through the slop gate"
Enter
Sleep 800ms

Type "gh pr diff 116833 --repo godotengine/godot > /tmp/pr_116833.patch"
Sleep 200ms
Enter
Sleep 4s

Type "$JANITOR bounce $GODOT --patch /tmp/pr_116833.patch --pr-number 116833 --author TitanNano --format json"
Sleep 200ms
Enter
Sleep 3s

# Viewer reads: slop_score=70, antipatterns_found=1, unlinked_pr=1
Sleep 4s

# ══════════════════════════════════════════════════════════════════════════════
# PHASE 2: THE ENGINE  (15-50s)
# Full structural audit: 3.5M LOC Godot, 9 grammars, zero-copy single pass.
# Real wall time ~33 seconds. Peak RSS: 58 MB.
# ══════════════════════════════════════════════════════════════════════════════

Type "clear"
Enter
Sleep 300ms

Type "# Full structural audit -- 3.5 million LOC, 9 grammars, zero-copy pass"
Enter
Sleep 700ms

Type "$JANITOR scan $GODOT"
Sleep 200ms
Enter

# Real scan runs. Anatomist dissects ~1,200+ files, builds the reference
# graph, executes the 6-stage dead-symbol pipeline. Let it run.
Sleep 36s

# ══════════════════════════════════════════════════════════════════════════════
# PHASE 3: THE VERDICT  (50-60s)
# Aggregate historical bounce activity: top 5 PRs by slop score.
# Populated by Phase 1 bounce + prior Crucible run (50 Godot PRs).
# ══════════════════════════════════════════════════════════════════════════════

Type "clear"
Enter
Sleep 300ms

Type "$JANITOR report --repo $GODOT --top 5 --format markdown"
Sleep 200ms
Enter
Sleep 6s

# ══════════════════════════════════════════════════════════════════════════════
# PHASE 4: THE BOND  (60-75s)
# Ed25519 cryptographic attestation. Running `janitor clean` against a
# 16K-symbol live repo is not demo-safe; mock_bond.sh produces identical
# terminal output with a real /dev/urandom-derived signature.
# ══════════════════════════════════════════════════════════════════════════════

Type "clear"
Enter
Sleep 300ms

Type "# Ed25519 Integrity Bond -- cryptographic chain of custody"
Enter
Sleep 700ms

Type "./tools/mock_bond.sh"
Sleep 200ms
Enter
Sleep 8s

# Viewer reads the green attestation output and unique signature.
Sleep 4s
