# Wraith Dependency and License Review

## Review scope and result

This review records every third-party Go module in the active module graph and every package manifest installed from the committed pnpm lockfile on **2026-08-17**. It is an engineering inventory, not legal advice. License identifiers are taken from each dependency's declared package metadata or top-level license text. A maintainer should repeat the review after any dependency change and obtain legal advice when distribution conditions are uncertain.

| Ecosystem | Reviewed package versions | Review result |
| --- | ---: | --- |
| Go modules | 33 | MIT, BSD-3-Clause, and Apache-2.0 only. No GPL-family or other strong-copyleft module was found. |
| Web pnpm packages | 116 | Predominantly permissive. Three `lightningcss` packages declare MPL-2.0, a file-level weak-copyleft license; see the exception note below. |

Wraith is licensed under the MIT License; see [`../LICENSE`](../LICENSE). This review covers third-party dependency licenses only and does not alter Wraith's own license terms.

## Change control

The CI workflow runs `bash scripts/check-dependency-review.sh go` in the Go job and `bash scripts/check-dependency-review.sh web` in the web job. The script compares the live `go list -m all` graph and installed locked pnpm package manifests to the literal module/package-and-version records in this document. A newly added or version-changed dependency fails CI until this review is updated. The check intentionally verifies **coverage**, not the legal correctness of a license classification.

For local validation, install the locked web dependency tree and run:

```sh
pnpm --dir web install --frozen-lockfile --ignore-scripts
bash scripts/check-dependency-review.sh
```

## Go module review

The table below excludes Wraith itself and covers every resolved third-party module in `go list -m all`.

| Module | Version | License | Notes |
| --- | --- | --- | --- |
| `github.com/dustin/go-humanize` | `v1.0.1` | MIT | Transitive. |
| `github.com/google/go-cmp` | `v0.5.9` | BSD-3-Clause | Transitive test dependency. |
| `github.com/google/pprof` | `v0.0.0-20240409012703-83162a5b38cd` | Apache-2.0 | Transitive. |
| `github.com/google/uuid` | `v1.6.0` | BSD-3-Clause | Transitive. |
| `github.com/josharian/native` | `v1.1.0` | MIT | Transitive. |
| `github.com/mattn/go-isatty` | `v0.0.24` | MIT | Transitive. |
| `github.com/mdlayher/arp` | `v0.0.0-20260528070854-93566ba168e9` | MIT | Direct. |
| `github.com/mdlayher/ethernet` | `v0.0.0-20220221185849-529eae5b6118` | MIT | Transitive. |
| `github.com/mdlayher/packet` | `v1.1.2` | MIT | Transitive. |
| `github.com/mdlayher/socket` | `v0.4.1` | MIT | Transitive. |
| `github.com/ncruces/go-strftime` | `v1.0.0` | MIT | Transitive. |
| `github.com/remyoudompheng/bigfft` | `v0.0.0-20230129092748-24d4a6f8daec` | BSD-3-Clause | Transitive. |
| `golang.org/x/crypto` | `v0.36.0` | BSD-3-Clause | Transitive. |
| `golang.org/x/mod` | `v0.16.0` | BSD-3-Clause | Transitive. |
| `golang.org/x/net` | `v0.38.0` | BSD-3-Clause | Transitive. |
| `golang.org/x/sync` | `v0.1.0` | BSD-3-Clause | Transitive. |
| `golang.org/x/sys` | `v0.31.0` | BSD-3-Clause | Transitive. |
| `golang.org/x/term` | `v0.30.0` | BSD-3-Clause | Transitive. |
| `golang.org/x/text` | `v0.23.0` | BSD-3-Clause | Transitive. |
| `golang.org/x/tools` | `v0.19.0` | BSD-3-Clause | Transitive. |
| `golang.org/x/xerrors` | `v0.0.0-20191204190536-9bdfabe68543` | BSD-3-Clause | Transitive. |
| `modernc.org/cc/v4` | `v4.21.4` | BSD-3-Clause | Transitive. |
| `modernc.org/ccgo/v4` | `v4.19.2` | BSD-3-Clause | Transitive. |
| `modernc.org/fileutil` | `v1.3.0` | BSD-3-Clause | Transitive. |
| `modernc.org/gc/v2` | `v2.4.1` | BSD-3-Clause | Transitive. |
| `modernc.org/libc` | `v1.55.3` | BSD-3-Clause | Transitive. |
| `modernc.org/mathutil` | `v1.6.0` | BSD-3-Clause | Transitive. |
| `modernc.org/memory` | `v1.8.0` | BSD-3-Clause | Transitive. |
| `modernc.org/opt` | `v0.1.3` | BSD-3-Clause | Transitive. |
| `modernc.org/sortutil` | `v1.2.0` | BSD-3-Clause | Transitive. |
| `modernc.org/sqlite` | `v1.34.5` | BSD-3-Clause | Direct. |
| `modernc.org/strutil` | `v1.2.0` | BSD-3-Clause | Transitive. |
| `modernc.org/token` | `v1.1.0` | BSD-3-Clause | Transitive. |

## Web pnpm package review

The web application has four declared runtime/build dependencies and seven declared development dependencies. The full resolved set below is deliberately recorded because the dashboard is built from the lockfile. The `direct` label means the package is declared in `web/package.json`; all other rows are transitive.

| Package | Version | License | Relationship |
| --- | --- | --- | --- |
| `@adobe/css-tools` | `4.5.0` | MIT | Transitive. |
| `@asamuzakjp/css-color` | `6.0.7` | MIT | Transitive. |
| `@asamuzakjp/dom-selector` | `8.3.2` | MIT | Transitive. |
| `@babel/code-frame` | `7.29.7` | MIT | Transitive. |
| `@babel/helper-validator-identifier` | `7.29.7` | MIT | Transitive. |
| `@babel/runtime` | `7.29.7` | MIT | Transitive. |
| `@bramus/specificity` | `2.4.2` | MIT | Transitive. |
| `@csstools/color-helpers` | `6.1.1` | MIT-0 | Transitive. |
| `@csstools/css-calc` | `3.3.0` | MIT | Transitive. |
| `@csstools/css-color-parser` | `4.2.0` | MIT | Transitive. |
| `@csstools/css-parser-algorithms` | `4.0.0` | MIT | Transitive. |
| `@csstools/css-syntax-patches-for-csstree` | `1.1.8` | MIT-0 | Transitive. |
| `@csstools/css-tokenizer` | `4.0.0` | MIT | Transitive. |
| `@exodus/bytes` | `1.15.1` | MIT | Transitive. |
| `@jridgewell/sourcemap-codec` | `1.5.5` | MIT | Transitive. |
| `@oxc-project/types` | `0.144.0` | MIT | Transitive. |
| `@rolldown/binding-linux-x64-gnu` | `1.2.4` | MIT | Transitive. |
| `@rolldown/binding-linux-x64-musl` | `1.2.4` | MIT | Transitive. |
| `@rolldown/pluginutils` | `1.0.1` | MIT | Transitive. |
| `@standard-schema/spec` | `1.1.0` | MIT | Transitive. |
| `@testing-library/dom` | `10.4.1` | MIT | Transitive. |
| `@testing-library/jest-dom` | `7.0.1` | MIT | Direct development dependency. |
| `@testing-library/react` | `16.3.2` | MIT | Direct development dependency. |
| `@types/aria-query` | `5.0.4` | MIT | Transitive. |
| `@types/chai` | `5.2.3` | MIT | Transitive. |
| `@types/deep-eql` | `4.0.2` | MIT | Transitive. |
| `@types/estree` | `1.0.9` | MIT | Transitive. |
| `@types/react` | `19.2.18` | MIT | Direct development dependency. |
| `@types/react-dom` | `19.2.4` | MIT | Direct development dependency. |
| `@typescript/typescript-linux-x64` | `7.0.2` | Apache-2.0 | Transitive. |
| `@vitejs/plugin-react` | `6.0.5` | MIT | Direct runtime/build dependency. |
| `@vitest/expect` | `4.1.10` | MIT | Transitive. |
| `@vitest/mocker` | `4.1.10` | MIT | Transitive. |
| `@vitest/pretty-format` | `4.1.10` | MIT | Transitive. |
| `@vitest/runner` | `4.1.10` | MIT | Transitive. |
| `@vitest/snapshot` | `4.1.10` | MIT | Transitive. |
| `@vitest/spy` | `4.1.10` | MIT | Transitive. |
| `@vitest/utils` | `4.1.10` | MIT | Transitive. |
| `ansi-regex` | `5.0.1` | MIT | Transitive. |
| `ansi-styles` | `5.2.0` | MIT | Transitive. |
| `aria-query` | `5.3.0` | Apache-2.0 | Transitive. |
| `aria-query` | `5.3.2` | Apache-2.0 | Transitive. |
| `assertion-error` | `2.0.1` | MIT | Transitive. |
| `bidi-js` | `1.0.3` | MIT | Transitive. |
| `chai` | `6.2.2` | MIT | Transitive. |
| `convert-source-map` | `2.0.0` | MIT | Transitive. |
| `css-tree` | `3.2.1` | MIT | Transitive. |
| `css.escape` | `1.5.1` | MIT | Transitive. |
| `csstype` | `3.2.3` | MIT | Transitive. |
| `data-urls` | `7.0.0` | MIT | Transitive. |
| `decimal.js` | `10.6.0` | MIT | Transitive. |
| `dequal` | `2.0.3` | MIT | Transitive. |
| `detect-libc` | `2.1.2` | Apache-2.0 | Transitive. |
| `dom-accessibility-api` | `0.5.16` | MIT | Transitive. |
| `dom-accessibility-api` | `0.6.3` | MIT | Transitive. |
| `entities` | `8.0.0` | BSD-2-Clause | Transitive. |
| `es-module-lexer` | `2.3.2` | MIT | Transitive. |
| `estree-walker` | `3.0.3` | MIT | Transitive. |
| `expect-type` | `1.4.0` | Apache-2.0 | Transitive. |
| `fdir` | `6.5.0` | MIT | Transitive. |
| `html-encoding-sniffer` | `6.0.0` | MIT | Transitive. |
| `indent-string` | `4.0.0` | MIT | Transitive. |
| `is-potential-custom-element-name` | `1.0.1` | MIT | Transitive. |
| `js-tokens` | `4.0.0` | MIT | Transitive. |
| `jsdom` | `30.0.1` | MIT | Direct development dependency. |
| `lightningcss` | `1.33.0` | MPL-2.0 | Transitive; weak-copyleft exception. |
| `lightningcss-linux-x64-gnu` | `1.33.0` | MPL-2.0 | Transitive; weak-copyleft exception. |
| `lightningcss-linux-x64-musl` | `1.33.0` | MPL-2.0 | Transitive; weak-copyleft exception. |
| `lru-cache` | `11.5.2` | BlueOak-1.0.0 | Transitive. |
| `lz-string` | `1.5.0` | MIT | Transitive. |
| `magic-string` | `0.30.21` | MIT | Transitive. |
| `mdn-data` | `2.27.1` | CC0-1.0 | Transitive. |
| `min-indent` | `1.0.1` | MIT | Transitive. |
| `nanoid` | `3.3.18` | MIT | Transitive. |
| `obug` | `2.1.4` | MIT | Transitive. |
| `parse5` | `8.0.1` | MIT | Transitive. |
| `pathe` | `2.0.3` | MIT | Transitive. |
| `picocolors` | `1.1.1` | ISC | Transitive. |
| `picomatch` | `4.0.5` | MIT | Transitive. |
| `postcss` | `8.5.26` | MIT | Transitive. |
| `pretty-format` | `27.5.1` | MIT | Transitive. |
| `punycode` | `2.3.1` | MIT | Transitive. |
| `react` | `19.2.8` | MIT | Direct runtime/build dependency. |
| `react-dom` | `19.2.8` | MIT | Direct runtime/build dependency. |
| `react-is` | `17.0.2` | MIT | Transitive. |
| `redent` | `3.0.0` | MIT | Transitive. |
| `require-from-string` | `2.0.2` | MIT | Transitive. |
| `rolldown` | `1.2.4` | MIT | Transitive. |
| `saxes` | `6.0.0` | ISC | Transitive. |
| `scheduler` | `0.27.0` | MIT | Transitive. |
| `siginfo` | `2.0.0` | ISC | Transitive. |
| `source-map-js` | `1.2.1` | BSD-3-Clause | Transitive. |
| `stackback` | `0.0.2` | MIT | Transitive. |
| `std-env` | `4.2.0` | MIT | Transitive. |
| `strip-indent` | `3.0.0` | MIT | Transitive. |
| `symbol-tree` | `3.2.4` | MIT | Transitive. |
| `tinybench` | `2.9.0` | MIT | Transitive. |
| `tinyexec` | `1.3.0` | MIT | Transitive. |
| `tinyglobby` | `0.2.17` | MIT | Transitive. |
| `tinyrainbow` | `3.1.1` | MIT | Transitive. |
| `tldts` | `7.4.10` | MIT | Transitive. |
| `tldts-core` | `7.4.10` | MIT | Transitive. |
| `tough-cookie` | `6.0.2` | BSD-3-Clause | Transitive. |
| `tr46` | `6.0.0` | MIT | Transitive. |
| `typescript` | `7.0.2` | Apache-2.0 | Direct development dependency. |
| `undici` | `8.10.0` | MIT | Transitive. |
| `vite` | `8.2.1` | MIT | Direct runtime/build dependency. |
| `vitest` | `4.1.10` | MIT | Direct development dependency. |
| `w3c-xmlserializer` | `5.0.0` | MIT | Transitive. |
| `webidl-conversions` | `8.0.1` | BSD-2-Clause | Transitive. |
| `whatwg-mimetype` | `5.0.0` | MIT | Transitive. |
| `whatwg-url` | `16.0.1` | MIT | Transitive. |
| `whatwg-url` | `17.1.0` | MIT | Transitive. |
| `why-is-node-running` | `2.3.0` | MIT | Transitive. |
| `xml-name-validator` | `5.0.0` | Apache-2.0 | Transitive. |
| `xmlchars` | `2.2.0` | MIT | Transitive. |

## MPL-2.0 exception and distribution caution

`lightningcss` and its two Linux platform bindings are transitive tooling packages in the pnpm graph. They declare MPL-2.0, which is a file-level weak-copyleft license. No GPL-family or AGPL-family package was identified in the reviewed Go or pnpm graph. This observation is not a conclusion about distribution obligations; before packaging, copying, or modifying third-party files, the project owner should review the current upstream license texts and seek qualified legal advice as necessary.

## References

The dependency versions are reproducible from [`go.mod`](../go.mod), [`go.sum`](../go.sum), [`web/package.json`](../web/package.json), and [`web/pnpm-lock.yaml`](../web/pnpm-lock.yaml). The enforcement implementation is [`scripts/check-dependency-review.sh`](../scripts/check-dependency-review.sh) and [`scripts/check-web-dependency-review.mjs`](../scripts/check-web-dependency-review.mjs).
