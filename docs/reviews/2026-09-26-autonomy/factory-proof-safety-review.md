# Independent safety review: bounded attempt fingerprint proof

Status: offline design review only, following the owner's approval of the bounded
proposal. No production change, authority, compatibility acceptance or performance
benefit is established. Ordinary APIs and all external observations remain full.

## Actual projection

`SqlContinuousRuntimeAttemptSources._fingerprint` has two branches. Only the
`ResolvedRuntimeAttemptSources` branch is in this pilot. Its input is
`detached_journal_value((value.sources, source_projection, provenance_projection,
state.dispatches))`, followed by `canonical_json_bytes` and SHA-256. The source
projection enumerates each original `state.captured.plan.sources` item and reads
`reference`, `closure`, `checkpoint`, `action`, `request`, `dispatches`,
`admission_payloads`, `descriptor`, and `unsent_key_payload`. The provenance
projection reads each original `RuntimeTableSnapshot` as
`(str(table.table.name), table.account_id, table.rows)`.

Do not substitute `semantic_value`, seal only the top token, or traverse an
invented broader owner/SQL graph. `_Resolved.references`, `selected`, `descriptors`
and `outcomes` are not directly in this fingerprint projection; their preceding
owner/reference/descriptor/outcome checks still run unchanged.

The detached converter gives Mapping precedence, hashes exact bytes to
`('bytes', length, sha256)`, recursively converts exact tuples, preserves exact
primitive scalars, and reflects dataclasses using **class qualified name** and
ordered fields except `_owner`/`_validated_values`. Remaining supported scalar
leaves reach the canonical converter, including enums and time/decimal values.

## Minimum admitted profile

- Exact `None`, `bool`, `int`, `str`, `bytes`, `tuple`, and finite exact `Decimal`;
  exact `date`; exact `datetime` whose tzinfo is the original `datetime.UTC`
  singleton. Reject subclasses and custom time providers before issuing a seal.
  Exact immutable scalar identity is enough to preserve its value once its
  conversion dependencies are fixed. A retained byte object's unchanged identity
  proves unchanged bytes, so another digest is not needed for this proof.
- Exact dictionaries with exact string keys and admitted values. Verify complete
  size and ordered key/value identities; no key equality/hashing callbacks. A
  reordering can conservatively fail even if sorted detached output would match.
- Exact `MappingProxyType` alone is **insufficient**: it can wrap an arbitrary
  Mapping with effectful methods. A narrowly explicit CPython profile may use the
  original pinned builtin `gc.get_referents(proxy)` only for that exact proxy,
  require one exact-dict referent, and pin/recheck that backing pointer. Inspect
  backing dict primitives directly; do not call proxy methods to discover its
  backing. No arbitrary graph traversal with GC is needed. Unsupported runtimes
  or shapes take the full path before seal issuance. This is runtime inspection,
  not historical provenance or immutable dict contents.
- Only reviewed original record classes with ordinary `type` metaclass, original
  object attribute access, and known direct member descriptors or ordinary data
  storage. Pin class/type/MRO and consumed lookup behavior; no custom properties,
  `__getattr__`, reflection overrides or transient computed getters. The field
  inventory must include ordered `__dataclass_fields__` entries, original exact
  `dataclasses.Field` objects and each field's `name` and `_field_type`, including
  metadata for fields currently excluded by the two-name filter. A renamed or
  reclassified field must not become invisible to the proof. Check instance
  shadowing of the class field inventory too if unslotted objects are admitted.
- Only explicitly reviewed original enum classes/members with original class
  module/qualified-name, MRO, member `_value_`/`_name_`, value descriptor/fget and
  ordinary access behavior. Admit only independently admitted immutable enum
  values. Member identity alone is not enough. Unknown enum classes fall back.
- For provenance Table names, pin the original expected Table object and the
  projected `.name` binding. If exact SQLAlchemy `quoted_name` is admitted,
  qualify its original `__str__` behavior/content. Do not turn this into a proof
  of SQL compilation or all Table internals. The original SQL reads and rechecks
  remain unchanged.
- Aliases are allowed only with complete edge accounting and a visited-object
  inventory that does not suppress mutable descendants. Cycles or unrecognized
  leaves are unsupported. Do not silently broaden existing admission or budgets.

A finite stdlib-only check on the verified CPython 3.12.13 runtime confirmed that
`gc.get_referents` returns the original exact backing dict for a normal proxy and
the custom Mapping instance for an effectful proxy, without invoking any custom
mapping method. It also confirmed that changing dict contents remains visible:
this check does not itself seal contents.

## Consumed behavior and transitive bindings

The same value graph can hash differently after a function/class mutation.
Identity of a Python function alone does not pin its `__code__`, defaults,
keyword defaults, closure cells or consumed module globals. The implementation
must specify a finite original-binding inventory for the actual admitted path,
not claim that the current handoff seal covers it.

At minimum audit the owner projection function; `detached_journal_value` and its
`Mapping`, `fields`, `is_dataclass`, `sha256` bindings; dataclasses `_FIELDS` and
`_FIELD` plus field/class lookup behavior; Mapping/ABC classification and registry
changes (a new virtual Mapping registration can alter an unchanged tuple or
record's dispatch); canonical byte/text/append/fallback/node/decimal functions;
JSON string encoder and the JSON dumps/JSONEncoder path used by enum nodes; the
outer SHA-256 binding; and the exact native/runtime types those paths consume.
Rechecking an ABC cache token is a conservative way to reject a changed virtual
registration state, provided the relevant ABC functions and classes are original.

Do not admit a custom-but-current function merely because it remains the same
object after issuance. Initial admission requires the reviewed original behavior.
Do not build a generic arbitrary-Python dependency framework: narrow or reject the
profile if the finite consumed behavior cannot be qualified. The supported fault
model assumes ordinary Python memory integrity; it is not protection against
arbitrary native-memory tampering or replacement of the trusted interpreter.

## Ownership and lifecycle handshake

A structural proof has no caller authority on its own. The source's private
method must authenticate an original registry-backed factory context before
substituting its one final fingerprint, in addition to running the unchanged
preceding source guards. Bind to:

- exact reader/source owner/current attempt token and original producer links;
- `_ACTIVE_FACTORY_READS[reader]` and `reader._factory_read`, the operation's
  original owner tuple, original thread and nonfailed active state;
- the genuine `_FACTORY_SCOPES` entry when an original factory read scope is
  required; do not accidentally admit standalone schema/account paths;
- exact registered daily episode/state, snapshot, composer consumer and current
  explicit borrow invocation; possession of an equal episode dataclass or copied
  proof is not enough.

Only the `_require_daily_episode` calls inside `_borrow_original_daily` may use
this proof. Issuance, entry, the final `_require_daily_episode` before
`_recheck_final`, and factory terminal verification remain full. An explicit
private borrow-call ticket should deny out-of-borrow/reentrant/replayed private
calls; no ambient thread-local bypass or public skip flag. Local imports within
the same package can resolve cycles without reversing architecture layers.

Unknown profile **before issuance** falls back to the existing full method.
Changed bindings or damaged/foreign proof **after issuance** poison the original
operation; do not reseal, adopt changed input, or silently fall back to rescue it.
Retire and release the proof before `_FactoryResult` / `_factory_structure`
construction. Their retained lifetimes must be disjoint to share the existing
16,384-container and 131,072-binding limits, with no extra independent allowance.
Every exit, cancellation and cleanup failure must retire the original registration
without replacing a primary exception or clearing another operation's state.

## Review and tests still required

Literal old fingerprint oracle on all admitted profiles; adversarial field/schema,
class/getter/function-code/ABC/enum/time/table-name and mapping-backing changes;
mutation from preceding callbacks; equal foreign/copied/reconstructed tokens;
wrong owner/episode/operation/thread; reentrancy and use after retirement;
unsupported profile with unchanged original errors/callback behavior; complete
external SQL/object/fence trace equivalence; exact boundary memory counts and
failed cleanup release. Show issuance plus every check plus retirement has useful
measured cost on the actual captured graph before claiming value. Original
retained acceptance and exact-revision CI remain separate requirements.
