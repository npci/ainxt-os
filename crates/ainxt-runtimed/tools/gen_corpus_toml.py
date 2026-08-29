# SPDX-License-Identifier: Apache-2.0
# Copyright 2024-2026 National Payments Corporation of India
"""Generate corpus.toml from a JSONL knowledge-base export.

MAINTAINER SCRIPT — not part of the build, and not runnable from a clean checkout.

It expects `corpus/upi_faq.jsonl` relative to the current working directory. That dataset is
India-specific UPI FAQ content and is NOT distributed in this repository, so running this against
a fresh clone raises FileNotFoundError. It is kept because the corpus mechanism it feeds is real:
`ainxt-runtimed` loads `corpus.toml` as a `--config` layer to populate the `[kb]` knowledge base
(see `crates/ainxt-runtimed/src/lib.rs`). Supply your own JSONL in the same shape to use it:

    {"id": "...", "source": "...", "text": "...", "data_class": "public",
     "attributes": {"department": "..."}}

Usage:  cd <dir containing corpus/>  &&  python3 gen_corpus_toml.py
"""
import json

entries = []
with open('corpus/upi_faq.jsonl') as f:
    for line in f:
        d = json.loads(line.strip())
        dept = d.get('attributes', {}).get('department', '')
        dept_line = f'\ndepartment = "{dept}"' if dept else ''
        text = d['text']
        entry = (
            f'[[kb.documents]]\n'
            f'id = "{d["id"]}"\n'
            f'source = "{d["source"]}"\n'
            f'text = """{text}"""\n'
            f'data_class = "{d["data_class"]}"{dept_line}\n'
        )
        entries.append(entry)

content = (
    '# AiNxt OS — Corpus documents (KB)\n'
    '# Loaded via: ainxt-runtimed --config config.toml --config corpus.toml\n'
    '# Add new documents here as [[kb.documents]] entries.\n'
    '# The runtime merges multiple --config layers, so config.toml stays clean.\n\n'
)
content += '\n'.join(entries)

with open('corpus.toml', 'w') as f:
    f.write(content)

print(f'Created corpus.toml with {len(entries)} documents')
