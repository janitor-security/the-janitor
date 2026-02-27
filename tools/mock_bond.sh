#!/usr/bin/env bash
# tools/mock_bond.sh — Ed25519 attestation with animated file-scan for VHS demo.
#
# Simulates: janitor clean ~/dev/gauntlet/godot --force-purge --token $JANITOR_TOKEN
# Animated scroll shows real Godot source paths being excised.

set -euo pipefail

DIM=$'\033[2m'
GRN=$'\033[32m'
YLW=$'\033[33m'
BLD=$'\033[1m'
NC=$'\033[0m'

# Real Godot source paths — used in the animated excision scroll
PATHS=(
  "core/math/vector3.cpp"
  "core/math/transform_3d.cpp"
  "core/math/geometry_3d.cpp"
  "core/io/file_access_zip.cpp"
  "core/io/resource_loader.cpp"
  "core/string/ustring.cpp"
  "core/variant/variant.cpp"
  "core/variant/array.cpp"
  "core/templates/hash_map.h"
  "core/templates/local_vector.h"
  "core/object/class_db.cpp"
  "core/os/memory.cpp"
  "servers/rendering/renderer_rd/storage_rd/light_storage.cpp"
  "servers/rendering/renderer_rd/storage_rd/mesh_storage.cpp"
  "servers/rendering/renderer_rd/storage_rd/texture_storage.cpp"
  "servers/rendering/renderer_rd/shaders/scene_forward_clustered.glsl"
  "scene/resources/material.cpp"
  "scene/resources/mesh.cpp"
  "scene/3d/physics_body_3d.cpp"
  "scene/3d/camera_3d.cpp"
  "scene/3d/light_3d.cpp"
  "editor/plugins/node_3d_editor_plugin.cpp"
  "editor/docks/scene_tree_dock.cpp"
  "editor/editor_node.cpp"
  "editor/editor_settings.cpp"
  "modules/gdscript/gdscript_parser.cpp"
  "modules/gdscript/gdscript_compiler.cpp"
  "drivers/gles3/storage/texture_storage.cpp"
  "drivers/gles3/rasterizer_scene_gles3.cpp"
  "platform/linuxbsd/x11/display_server_x11.cpp"
  "platform/macos/display_server_macos.mm"
)

echo ""
echo "  janitor clean ~/dev/gauntlet/godot --force-purge --token \$JANITOR_TOKEN"
echo ""
sleep 0.5

printf "  %s[shadow tree]%s  Symlinking 7,812 dead-symbol files into .janitor/shadow_src/\n" \
  "$DIM" "$NC"
sleep 0.5

# ── Animated excision scroll — 3 seconds ──────────────────────────────────────
printf "  %s[reaper      ]%s  Excising symbols...\n" "$YLW" "$NC"
sleep 0.2

END=$((SECONDS + 3))
I=0
while [ "$SECONDS" -lt "$END" ]; do
  IDX=$((I % ${#PATHS[@]}))
  printf "\r  %s  ↳ %-68s%s" "$DIM" "${PATHS[$IDX]}" "$NC"
  I=$((I + 1))
  sleep 0.09
done
printf "\r  %-75s\n" ""   # erase the scroll line
# ── End scroll ────────────────────────────────────────────────────────────────

sleep 0.3
printf "  %s[shadow tree ]%s  Running test suite in isolation...\n" "$DIM" "$NC"
sleep 1.6

printf "  %s[PASS         ]%s  Shadow test suite clean. Proceeding to bond issuance.\n" \
  "$GRN" "$NC"
sleep 0.5

printf "  %s[INTEGRITY BOND]%s  Ed25519 audit log sealed\n" "$GRN" "$NC"
sleep 0.4

# Generate a deterministic-looking 8-char hex for the bond filename
HASH=$(od -An -N4 -tx4 /dev/urandom | tr -d ' \n')
printf "  %s[INTEGRITY BOND]%s  .janitor/bonds/116833_%s.json  —  7812 entries  SHA-256 chained\n" \
  "$GRN" "$NC" "${HASH:0:8}"
sleep 0.4

SIG=$(head -c 48 /dev/urandom | base64 | tr -d '\n=' | cut -c1-88)
printf "  %s[INTEGRITY BOND]%s  Signature: %s%s%s\n" "$GRN" "$NC" "$BLD" "$SIG" "$NC"
sleep 0.3

echo ""
printf "  %s%s RECLAMATION COMPLETE.%s  7,812 dead symbols excised.\n" \
  "$BLD" "$GRN" "$NC"
printf "                          Bond: .janitor/bonds/116833_%.8s.json\n" "$HASH"
echo ""
