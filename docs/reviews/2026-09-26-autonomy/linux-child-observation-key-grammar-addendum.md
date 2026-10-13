# Linux child observation key grammar correction

2026-09-27. This correction supplements the completeness-marker addendum. Preserve both earlier candidates, static artifacts and review records as historical evidence. Reviews of candidate `21a3684d24ad069fa91b98597328bb556ed24614d7231655392daaa355eb322a` are provisional for this revised version.

Parent review found that a row such as ` VmRSS: bad` was ignored as an unrelated key. A no-memory record containing that malformed row could consequently return zero. The correction rejects malformed status keys before field selection: the first byte must be an ASCII letter or underscore, and subsequent bytes must be ASCII letters, decimal digits or underscore. No stripping, case normalization or decoding is performed. Raw values, including arbitrary non-ASCII or carriage-return bytes in Name, remain unchanged.

This is a bounded grammar check on the already bounded status payload. It adds no process observation, authority, retry, fallback, deadline, state interpretation or memory limit. The mandatory late marker and all fd/deadline/error-precedence behavior are unchanged. As before, this is not attestation against selective line deletion or fabricated procfs data.

The test owner is adding malformed whitespace/control/non-ASCII/punctuation/numeric-leading keys both before and after the marker, plus valid underscore and digit-containing names. Candidate author performed only syntax compilation and AST preservation checks, with no project import or test execution.

Source SHA256: `0f4f9b925c14d14f4535086d9a05ad8d0d3e9a7b088bde5c712d53f1a57c6517`.
Revised candidate SHA256: `a7b98cf8e11036068a002f7ca56516c973bf84e7315ae9fbf4e031b42cdd6655`.
Static evidence: `linux-child-native-static-check-v3.json`.
