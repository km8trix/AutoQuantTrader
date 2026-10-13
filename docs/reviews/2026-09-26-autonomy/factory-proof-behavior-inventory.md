# Finite behavior inventory for the unconnected factory fingerprint pilot

Historical design checkpoint, preserved from before source integration. It
describes costs missing from the initial raw-data benchmark; it is not the current
implementation status. The subsequently implemented candidate is documented in
[ARCHITECTURE](../../ARCHITECTURE.md), with [cross-boundary review](factory-proof-cross-boundary-review.md)
and [complete observed cost model](factory-proof-complete-economics.json).

## Trust and baseline boundary

The fault model is ordinary Python/import/native-memory integrity, including
application-level rebinding and object/schema mutation. It cannot promise safety
against arbitrary replacement of both private baseline storage and its verifier,
interpreter corruption, hostile native memory writes, or monkeypatching the
trusted import mechanism before project import. This assumption must be explicit.

Capture reviewed original code at module initialization, not arbitrary code first
seen at proof issuance. The source module can snapshot its methods after class
creation. Because continuous_integrity imports the source module, root helpers
are defined later: an exact once-only source registration at root module completion
can store its module and original tuple. A later registration must fail rather
than overwrite baseline. This is a same-package import handshake, not caller
execution authority; the existing authenticated root registry supplies authority.

A Python function record must bind the original function object, `__code__`,
`__defaults__`, `__kwdefaults__`, `__closure__` and closure-cell contents where any
exist, plus its original globals/builtins namespaces and a manually reviewed finite
set of consumed bindings. Mutable default/closure containers cannot be certified
by pointer alone. Prefer rejecting unexpected default/closure profiles to adding
another general graph mechanism. Builtin functions/types use exact identities;
source and root class method descriptors must remain the original descriptors.

## Source projection and existing guard path

Bind these original source methods and their directly consumed name bindings:

- `_fingerprint`: ResolvedRuntimeAttemptSources, `_Resolved`, `cast`,
  `detached_journal_value`, `canonical_json_bytes`, `sha256`; builtin `type`,
  `tuple` and `str`. Its generator code objects are constants within the pinned
  outer code object. Prepared-branch behavior is never replaced.
- Public `require_resolved` plus private issue/check/retire methods: their original
  bodies must remain unchanged after baseline. The private check must run the
  same preceding `_require`, references, descriptor and outcome checks in order.
- `_require`, `_require_bindings`, `_binding_values`, `_outcome_reader`: bind
  source method descriptors/code and exact source owner links. Their calls still
  execute; pinning does not replace any owner verification or nested dependency
  validation. Root must independently continue its original producer/owner guards.

The proof's expected digest must be the same original entry from the source's
existing `_fingerprints`, not a recomputed substitute supplied by a caller. Source
registration binds original self/value/context/thread and cannot be reused by a
copy sharing the original dictionaries. Proof/token internals do not themselves
confer ownership; exact registry identity is required.

## Detached conversion and dispatch

Bind the original `detached_journal_value`, its module namespace and consumed
`Mapping`, `fields`, `is_dataclass`, `sha256` and recursive function bindings.
Bind builtin `type`, `bytes`, `len`, `isinstance`, `tuple`, `str`, `sorted`,
`getattr` and their actual function builtin-namespace bindings. Do not infer these
from another module's similarly named objects.

Bind original dataclasses `fields` and `is_dataclass` functions, their `_FIELD`
and `_FIELDS` dependencies and consumed builtins. The data seal already checks
ordered schema maps, original exact Field objects and name/kind values, including
currently filtered fields. It additionally needs the original `__class__` lookup
path: `isinstance` may consult it even for an unchanged exact object.

The Mapping branch takes precedence. Initial admission must prove each accepted
profile has the same Mapping classification as the literal converter; a token
only establishes that registrations did not change *after* issuance. Reject
preexisting virtual-Mapping dataclasses/scalars instead of treating them as record
or scalar leaves. Classification must not invoke arbitrary virtual-registration
or custom-metaclass hooks. A possible narrow policy is to qualify the original
stdlib Mapping/ABC implementation and its initial registry profile, with exact
native registry members only, then conservatively reject any changed token or
unsupported registry state. That profile needs a finite test before adoption;
blind `isinstance` during admission is not a no-callback proof. Do not add broad
ABC-registry introspection without demonstrating necessity and bounded cost.

## Canonical conversion

Pin the original functions and their consumed module/builtin bindings:
`canonical_json_bytes`, `canonical_json_text`, `_append_typed_text`,
`_typed_fragment_text`, `_typed_node`, `_json_text`, `canonical_decimal_text` and
`canonical_decimal`. Include recursive bindings and the exact `json`, `Enum`,
`Decimal`, `datetime`, `date`, `UTC`, `UUID` and Mapping identities, even where an
unsupported leaf causes fallback before the pilot is admitted. Pin integer digit
limit getter identity/value. Exact native finite Decimal and exact UTC date/time
objects prevent mutable arithmetic context/timezone callbacks on accepted leaves.

For emitted exact strings/ints/bytes, pin `json.encoder.encode_basestring_ascii`
and its module binding. Enum nodes use `_json_text`, so JSON behavior remains a
real dependency: `json.dumps`, the exact JSONEncoder class, original class/MRO/
lookup structure, `__init__`, `encode`, `iterencode`, `default`, separators and
native encoder bindings must be qualified. On a fixed CPython profile, requiring
the original non-None C encoder narrows the branch; otherwise use full fallback.
Do not silently assume pinning `json.dumps` also pins its class or mutable globals.
The new JSONEncoder instance's original constructor still follows fixed arguments;
new class data descriptors could change those writes/reads and must be rejected.
A whole small original class dictionary inventory may be simpler than incomplete
per-method pins, but its references and validation cost must be charged.

Enums need original Enum property descriptors *and* their fget/code/default/global
behavior, original enum class module/qualified-name/member state and ordinary
lookup. SQLAlchemy quoted_name needs original class lookup and `__str__`; Table
needs only its exact original instance/name lookup, since no SQL compilation is
being replaced. Do not expand this proof to mutable SQL expression trees.

## Root permit and failure lifecycle

Root provides its fixed `_FACTORY_FINGERPRINT_ORIGINAL_FUNCTIONS` inventory at
module completion, containing agreed context/begin/end/retire helpers, their
owner/use/fail dependencies, and reader issue/retire/begin/end-borrow/daily-graph/
daily-episode/borrow methods. Store original function records, root error/type
identities and exact consumed registry mappings. Registry identity pinning must
not freeze legitimate per-operation entries: existing root validation continues
to authenticate current registered ownership/phase/one-use state each time.

No authenticated use exists without the genuine original_factory_read scope,
original entering/HALTED operation, daily episode, original source/value/thread
and explicit active borrow invocation. The one-use ticket transitions ready →
checking → complete. A failed or caught/reentrant private use poisons the owning
operation. Root retirement must revoke registration even when data checks fail;
source cleanup must release its original registration in `finally` without
replacing the original exception or removing another operation's proof.

Proof lifetime ends before the handoff inventory is constructed. Add all behavior
records, owner/context/permit edges and retained closure references to the original
16,384-container/131,072-binding allowance; no second cap. Record each baseline
configuration reference once where possible, but do not suppress each distinct
object-edge charge. Measure full issuance, each permitted check, failure cleanup
and normal retirement after implementation, not only the raw-data walk.

## Required adverse checks beyond the existing 39 pure cases

Before issuance: original function replacement or in-place code/default mutation;
preexisting Mapping registration; custom `__class__`; altered JSONEncoder data
lookup; root registration already populated; unexpected closure/default shapes;
unsupported runtime or native encoder. These must retain the original full path
or fail the existing authenticated operation as specified, never bless a changed
function as the original baseline.

After issuance: every direct/global/class/descriptor/code binding mutation;
mutation from each preceding original owner callback; equal foreign/copy tokens;
foreign thread, operation, source, episode or borrow; reentrant/reused tickets;
failed use caught by caller; canceled scope; cleanup failures; stale later/restart
use; exact combined resource edges and graph collection after all retire paths.
Instrument original code with profiling/events, not monkeypatches that replace the
very methods being qualified. Full owner/factory, SQL, artifact and fence traces
must remain observationally present. Original retained acceptance and exact-source
Linux CI remain separate gates.
