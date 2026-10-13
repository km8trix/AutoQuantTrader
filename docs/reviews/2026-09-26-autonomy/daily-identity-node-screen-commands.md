# Commands executed for the per-node resource screen

2026-09-26. Historical command record only. No commands or tests were rerun to create this document. All work was confined to temporary files; these commands import no project module and construct no source owner, graph proof, database or genuine fixture.

## Final mechanics run

Exact command executed:

```sh
env -i PATH=/usr/bin:/bin PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=/private/tmp/aqt-autonomy-audit PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 TZ=UTC /Users/spencer.karrat/Documents/AutoQuantTrader/.wave4-runtime/2026-09-13/venv/bin/python -B -m pytest -q -p no:cacheprovider /private/tmp/aqt-autonomy-audit/test_daily_identity_node_screen.py > /private/tmp/aqt-autonomy-audit/daily-identity-node-screen-selfchecks.txt 2>&1
cat /private/tmp/aqt-autonomy-audit/daily-identity-node-screen-selfchecks.txt
```

Result: **37 passed in 0.03s**. These test scalar accounting and evidence qualification, not graph admission, mutation/lifecycle correctness or performance.

## Compilation during final preparation

Compilation was performed at the end of the following actual preparation heredoc. This is preserved in full to avoid falsely reporting a separate compilation process that did not occur. **Do not replay this preparation command:** its edit/rename steps belong to the historical artifact preparation and would disturb frozen outputs. The final loop used Python's `compile` directly, without imports of those sources or bytecode writes; both sources compiled successfully.

```sh
/Users/spencer.karrat/Documents/AutoQuantTrader/.wave4-runtime/2026-09-13/venv/bin/python -I -B - <<'PY'
from pathlib import Path
root=Path('/private/tmp/aqt-autonomy-audit')
p=root/'daily-identity-node-layout.md'
s=p.read_text().replace(" The proposal's old decision-pending label is historical to the approval; root owns its durable update.", '')
p.write_text(s)
p=root/'daily_identity_node_screen.py'
s=p.read_text().replace('import json\n','import json\nimport os\n').replace("    with path.open('xb') as handle:\n        handle.write(output)","    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)\n    with os.fdopen(descriptor, 'wb') as handle:\n        handle.write(output)")
p.write_text(s)
p=root/'test_daily_identity_node_screen.py'
s=p.read_text().replace('from pathlib import Path\n','')
p.write_text(s)
output=root/'daily-identity-node-layout-resource-screen.json'
output.rename(root/'daily-identity-node-layout-resource-screen.first-draft.json')
for name in ('daily_identity_node_screen.py','test_daily_identity_node_screen.py'):
 compile((root/name).read_text(),str(root/name),'exec')
print('Both temporary sources compile without imports or bytecode writes.')
PY
```

The earlier draft report was preserved separately; it is not the final report bound in the validation manifest.

## Frozen scalar report

Exact command executed after the final mechanics run:

```sh
env -i PATH=/usr/bin:/bin PYTHONDONTWRITEBYTECODE=1 /Users/spencer.karrat/Documents/AutoQuantTrader/.wave4-runtime/2026-09-13/venv/bin/python -I -B /private/tmp/aqt-autonomy-audit/daily_identity_node_screen.py
```

Result: `rejected_this_per_node_layout`.

The script verified the exact SHA256 of the already completed authentic observation and all nine original source/observer hashes. It wrote `daily-identity-node-layout-resource-screen.json` with **exclusive one-shot creation and mode 0600**. The final report SHA256 is `60d3ce0e7242beaddab93138939dbe033797473826da301a208f36dd9592413f`.

**Do not overwrite, remove or rename that frozen report to rerun the command.** Running the script again with its fixed output path is expected to refuse the existing output. Any separately justified future diagnostic would need a reviewed new path and identity, not a replacement of this evidence. No further fixture or timing run is needed for this rejection.

The final source/test/layout/report/log hashes and compile/mechanics result are recorded in `daily-identity-node-screen-validation.json`. The layout's joint lower bound is 16,743 containers and 139,661 bindings, exceeding the original caps by 359 and 8,589 respectively before nonnegative omitted charges. This rejects only the explicitly stated per-node representation; it establishes no universal impossibility and authorizes no alternate packing, deduplication, proof issuance or production substitution.
