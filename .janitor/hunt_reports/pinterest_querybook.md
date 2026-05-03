# Hunt Report — pinterest/querybook

**Sprint**: Batch 98  
**Date**: 2026-05-03  
**Engagement**: pinterest_targets  
**Repo**: https://github.com/pinterest/querybook (--depth 1)  
**Hunter**: janitor hunt /tmp/querybook-hunt --format bugcrowd  

## Findings

### 1. security:react_xss_dangerous_html

**Files**:
- `querybook/webapp/components/Search/SearchResultItem.tsx` (lines 58, 171, 287, 388, 494)
- `querybook/webapp/components/DataDocStatementExecution/StatementLog.tsx` (line 106)

**Severity**: High  
**Approval%**: 42% — dangerouslySetInnerHTML sinks confirmed present; IFDS solver
cannot trace whether the props flowing into `__html` originate from a user-controlled
SQL query result or from server-sanitized metadata. No concrete repro_cmd produced.

**Lattice gap**: IFDS does not model React component prop taint chains across
server-rendered API responses → `dangerouslySetInnerHTML.__html`. Framework-emergent
taint through Express/Django REST → React JSX props is invisible to the current solver.

**Dual-Ledger Mandate**: P3-8 (Thermodynamic CI) is the highest-priority open item.
A new capability gap entry for React/Express taint chain modeling will be filed in
a future sprint to unlock this class of finding to >85% Approval%.

**Exploitation Strategy** (manual, Approval% elevation path):  
1. Grep querybook's Express/Django routes for endpoints that return `name`, `title`,
   or `description` fields fed directly from user-created DataDoc metadata.  
2. Verify that `SearchResultItem` receives `result.title` or `result.description`
   from an API response containing unsanitized user input.  
3. Inject `<img src=x onerror=alert(document.domain)>` as a DataDoc title via
   the API, then trigger a search that renders that result in `SearchResultItem`.  
4. If the payload renders without escaping → weaponized stored XSS, Approval% >85%.

### 2. security:os_command_injection

**File**: `querybook/server/models/user.py` line 55  
**Approval%**: 25% — Python model file; without seeing the actual sink (subprocess
call or eval), the location (models layer) suggests admin-level DB access required
to reach it. Not a remote code execution path without auth bypass. No repro_cmd.
Entry not logged to Bounty Ledger (Approval% < 10% without exploitation proof).
