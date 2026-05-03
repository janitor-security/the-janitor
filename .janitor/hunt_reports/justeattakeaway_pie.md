# Hunt Report — justeattakeaway/pie

**Sprint**: Batch 98  
**Date**: 2026-05-03  
**Engagement**: takeaway.com_targets  
**Repo**: https://github.com/justeattakeaway/pie (--depth 1)  
**Hunter**: janitor hunt /tmp/justeattakeaway-hunt --format bugcrowd  

## Result: no_findings

Structural Eradication Law applied — path guard added to `is_excluded_hunt_file`
in `crates/cli/src/hunt.rs` to suppress false positives from known vendor
syntax-highlighting libraries and documentation-only site paths.

Findings reviewed:

- `security:dom_xss_innerhtml` in `apps/pie-docs/src/assets/js/prism.js` (line 4) —
  `prism.js` is the industry-standard syntax highlighting library universally bundled
  into documentation sites. Its `innerHTML` usage is intentional, sandboxed to
  pre-formatted code blocks, and not reachable from user-controlled input in a
  documentation context. Path guard `name == "prism.js"` added to
  `is_excluded_hunt_file`. Re-run confirmed finding absent.

- `security:dom_xss_innerhtml` in `apps/pie-docs/src/assets/js/categorised-icon-list-filter.js`
  (lines 8, 18) — file is in `apps/pie-docs/src/assets/`, a documentation-only site
  path. Path guard `path_str.contains("/pie-docs/")` added to `is_excluded_hunt_file`.
  Re-run confirmed finding absent.

The `pie-docs` application is a Storybook-style component documentation browser,
not the production JustEatTakeaway consumer application. No production attack surface
is present in this repository.
