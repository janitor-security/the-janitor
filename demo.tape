Output demo.mp4
Set Theme "Catppuccin Mocha"
Set FontFamily "FiraCode Nerd Font"
Set FontSize 14
Set Width 1200
Set Height 800
Set WindowBar Colorful
Set TypingSpeed 50ms
Set Padding 24

# ── Hidden preamble: env + PATH shim + pre-fetch PR patch ─────────────────────
Hide
Type "cd ~/dev/the-janitor"
Enter
Type "export GODOT=~/dev/gauntlet/godot"
Enter
Type "mkdir -p /tmp/_jdemo && ln -sf ~/dev/the-janitor/tools/demo_janitor.sh /tmp/_jdemo/janitor && chmod +x /tmp/_jdemo/janitor"
Enter
Type "export PATH=/tmp/_jdemo:$PATH"
Enter
Type "export PS1='[janitor] $ '"
Enter
Type "gh pr diff 116833 --repo godotengine/godot > /tmp/pr_116833.patch 2>/dev/null"
Enter
Sleep 4s
Show

# ══════════════════════════════════════════════════════════════════════════════
# PHASE 1: THE STRIKE  (0–12s)
# Viewer sees: janitor bounce ~/dev/gauntlet/godot
# Routes via demo_janitor.sh → mock_bounce.sh
# Real Crucible data: slop_score=70, antipatterns=1, unlinked=1
# ══════════════════════════════════════════════════════════════════════════════

Type "janitor bounce ~/dev/gauntlet/godot"
Sleep 200ms
Enter
Sleep 7s

# ══════════════════════════════════════════════════════════════════════════════
# PHASE 2: THE ENGINE  (12–50s)
# Real janitor scan: 3.5M LOC, 9 grammars, ~33s wall time, 58 MB peak RSS.
# ══════════════════════════════════════════════════════════════════════════════

Type "clear"
Enter
Sleep 300ms

Type "# 3.5M LOC  ·  9 grammars  ·  zero-copy  ·  58 MB peak RSS"
Enter
Sleep 700ms

Type "janitor scan $GODOT"
Sleep 200ms
Enter
Sleep 36s

# ══════════════════════════════════════════════════════════════════════════════
# PHASE 3: THE VERDICT  (50–58s)
# Historical bounce intelligence: top 5 PRs by slop score.
# Reads .janitor/bounce_log.ndjson populated by The Crucible (50 Godot PRs).
# ══════════════════════════════════════════════════════════════════════════════

Type "clear"
Enter
Sleep 300ms

Type "janitor report --repo $GODOT --top 5 --format markdown"
Sleep 200ms
Enter
Sleep 6s

# ══════════════════════════════════════════════════════════════════════════════
# PHASE 4: THE BOND  (58–80s)
# Ed25519 integrity attestation with animated excision scroll.
# ══════════════════════════════════════════════════════════════════════════════

Type "clear"
Enter
Sleep 300ms

Type "# Integrity Bond  —  Ed25519 chain of custody"
Enter
Sleep 600ms

Type "./tools/mock_bond.sh"
Sleep 200ms
Enter
Sleep 12s

Sleep 4s
