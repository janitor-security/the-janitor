Output demo.mp4
Set Theme "Catppuccin Mocha"
Set FontFamily "FiraCode Nerd Font"
Set FontSize 14
Set Width 1200
Set Height 800
Set WindowBar Colorful
Set TypingSpeed 50ms
Set Padding 24

# ── Hidden preamble ────────────────────────────────────────────────────────────
Hide
Type "cd ~/dev/the-janitor"
Enter
Type "export GODOT=~/dev/gauntlet/godot"
Enter
Type "export JANITOR=~/dev/the-janitor/target/release/janitor"
Enter
Type "export PS1='[janitor] $ '"
Enter
Type "gh pr diff 116833 --repo godotengine/godot > /tmp/pr_116833.patch 2>/dev/null"
Enter
Sleep 4s
Show

# ══════════════════════════════════════════════════════════════════════════════
# PHASE 1: THE STRIKE  (0–10s)
# PR #116833 — TitanNano — slop_score=70, antipattern×1, unlinked×1
# ══════════════════════════════════════════════════════════════════════════════

Type "./tools/mock_bounce.sh"
Sleep 200ms
Enter
Sleep 7s

# ══════════════════════════════════════════════════════════════════════════════
# PHASE 2: THE ENGINE  (10–48s)
# Real janitor scan: 3.5M LOC, 9 grammars, ~33s wall time, 58 MB peak RSS.
# ══════════════════════════════════════════════════════════════════════════════

Type "clear"
Enter
Sleep 300ms

Type "# 3.5M LOC  --  9 grammars  --  zero-copy  --  58 MB peak RSS"
Enter
Sleep 700ms

Type "$JANITOR scan $GODOT"
Sleep 200ms
Enter
Sleep 36s

# ══════════════════════════════════════════════════════════════════════════════
# PHASE 3: THE VERDICT  (48–56s)
# Top 5 PRs by slop score from the Crucible bounce log (50 Godot PRs).
# ══════════════════════════════════════════════════════════════════════════════

Type "clear"
Enter
Sleep 300ms

Type "$JANITOR report --repo $GODOT --top 5 --format markdown"
Sleep 200ms
Enter
Sleep 6s

# ══════════════════════════════════════════════════════════════════════════════
# PHASE 4: THE BOND  (56–78s)
# Governor-issued ML-DSA-65 (FIPS 204) CBOM with animated excision scroll.
# the-governor/src/compliance/pqc.rs implements fips204::ml_dsa_65.
# ══════════════════════════════════════════════════════════════════════════════

Type "clear"
Enter
Sleep 300ms

Type "# Governor Bond  --  ML-DSA-65 (FIPS 204) chain of custody"
Enter
Sleep 600ms

Type "./tools/mock_bond.sh"
Sleep 200ms
Enter
Sleep 12s

Sleep 4s
