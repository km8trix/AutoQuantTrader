# Native observer v3 key-grammar review

2026-09-27. Independently reviewed only the delta from approved v2 candidate `21a3684d24ad069fa91b98597328bb556ed24614d7231655392daaa355eb322a` to v3 `a7b98cf8e11036068a002f7ca56516c973bf84e7315ae9fbf4e031b42cdd6655`.

**No blocker to implementation and the pending validation.** Each status key must now begin with an ASCII letter or underscore and contain only ASCII letters, digits or underscores thereafter. Validation happens before key dispatch, so whitespace or control characters cannot disguise a memory key as an ignored unrelated field and admit zero RSS. The parser does not strip or normalize malformed names.

The literal diff changes only this key predicate. Existing valid kernel key names and raw values, including Name contents, keep their interpretation; malformed keys fail closed. The supplied byte/deadline bounds, mandatory late marker, RSS/state semantics, descriptor closure, ps fallback-platform body and sole-waiter protocol are unchanged. Unknown syntactically valid unrelated fields retain the existing ignored-field policy; this is not an arbitrary forged-record attestation.

Prior v2 review remains applicable to unchanged code. No candidate imports, tests, fixture runs or production edits were performed by this reviewer. The author separately reports compile and AST-preservation checks in `linux-child-native-static-check-v3.json`; root owns behavioral validation and acceptance.
