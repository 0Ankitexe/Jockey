# Synthetic collection-contract examples

These files are authored offline, not collected from a computer. All authority
dates are deliberately expired. They never designate a workstation or permit
a live collection. The report is labelled `synthetic_test`.

`fixtures/collection-cases.json` is the test index. Each case names its schema,
validation layer and expected result/reason. The companion invalid directory
includes malformed raw JSON, not just schema-invalid objects. Both Rust and
Python run the corpus without remote schema retrieval.

Individual record variants exercise closed payload shapes; their standalone
presence is not proof of authority, source observations, custody or a valid
enclosing report. Wire decoding does not replace independent report integrity
verification. Never relabel these fixtures as live acceptance evidence.
