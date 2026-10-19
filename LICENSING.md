# Pakomichi licensing

Status: **approved by the project owner** and recorded in ADR-016. Pakomichi deliberately separates software and code-like material from documentation prose so that examples can be reused in software and books without ShareAlike ambiguity.

## Source code and code-like material

Original Pakomichi source code and code-like material are offered, at the recipient's choice, under **MIT OR Apache-2.0**:

- [MIT License](LICENSE-MIT);
- [Apache License 2.0](LICENSE-APACHE).

This category includes source files, code blocks embedded in documentation, shell commands, configuration examples, schemas, machine-readable examples, test fixtures, and other material intended to be copied into or executed as part of software. For a Markdown file containing both prose and code blocks, this software license applies to the code-like parts while the prose follows the documentation license below.

The recipient may choose either MIT or Apache-2.0 for applicable material; compliance with both at once is not required. Both licenses permit commercial use, modification, and redistribution, including proprietary derivative works, subject to the selected license's conditions. Apache-2.0 includes an explicit patent grant and related conditions; MIT does not contain an equivalent explicit patent grant.

Use the exact SPDX expression `MIT OR Apache-2.0` in source-code licensing metadata and source headers.

## Documentation prose

Original Pakomichi documentation prose and original diagrams are licensed under the **Creative Commons Attribution 4.0 International License (`CC-BY-4.0`)**. The complete legal text is in [LICENSE-DOCS](LICENSE-DOCS), and the canonical license page is <https://creativecommons.org/licenses/by/4.0/>.

CC BY 4.0 permits sharing and adaptation, including commercial use, provided that appropriate credit is given, a license reference is supplied, and modifications are indicated. A reasonable attribution for owner-authored material is: “Pakomichi documentation, Copyright © 2026 Fyodor Malkov, licensed under CC BY 4.0.” Preserve any additional attribution supplied with a contribution.

Use `CC-BY-4.0` for metadata that describes documentation prose alone. Do not put a single CC SPDX header on a mixed document if that would imply that embedded code examples are licensed only under CC BY 4.0; refer to this file instead.

## Contributions

Incoming source code and code-like contributions follow `MIT OR Apache-2.0`. Incoming documentation prose and original diagrams follow `CC-BY-4.0`. Contributors retain their copyright. See [CONTRIBUTING.md](CONTRIBUTING.md) for the submission terms.

## Boundaries

- These licenses apply only to material for which the Pakomichi contributors have authority to grant the stated rights.
- Pakomichi licensing does not change the licenses of third-party programs, `.deb`/`.rpm` packages, libraries, copied text, images, or other external material that Pakomichi serves or uses.
- Third-party material retains its own license, copyright, attribution, and notice requirements. Mark it clearly instead of applying Pakomichi's default licenses.
- Required notices for redistributed dependency material are collected in [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md); that material retains the stated third-party terms.
- Trademarks, the logo, and the right to present work publicly as an official Pakomichi project are not automatically licensed with source code or documentation.
