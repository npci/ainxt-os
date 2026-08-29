# SPDX-License-Identifier: Apache-2.0
# Copyright 2024-2026 National Payments Corporation of India
"""Generate corpus.toml from corpus/upi_faq.jsonl

SEC-F-001 fix: this used to build corpus.toml by pasting each document's text directly
into an f-string quoted with a triple-quote TOML multi-line-string marker. If a source
document's text happened to contain that same three-character marker, the string would
end early and whatever followed would become new, uncontrolled TOML content merged into
the config layer the runtime loads at startup. Building the file through tomli_w instead
means every value is escaped automatically by a real TOML writer, so no document's text
can ever break out of its own field, regardless of what characters it contains.
"""
import json

import tomli_w

documents = []
with open('corpus/upi_faq.jsonl') as f:
    for line in f:
        d = json.loads(line.strip())
        doc = {
            'id': d['id'],
            'source': d['source'],
            'text': d['text'],
            'data_class': d['data_class'],
        }
        dept = d.get('attributes', {}).get('department', '')
        if dept:
            doc['department'] = dept
        documents.append(doc)

header = (
    '# AiNxt OS — Corpus documents (KB)\n'
    '# Loaded via: ainxt-runtimed --config config.toml --config corpus.toml\n'
    '# Add new documents here as [[kb.documents]] entries.\n'
    '# The runtime merges multiple --config layers, so config.toml stays clean.\n\n'
)

with open('corpus.toml', 'wb') as f:
    f.write(header.encode('utf-8'))
    tomli_w.dump({'kb': {'documents': documents}}, f)

print(f'Created corpus.toml with {len(documents)} documents')
