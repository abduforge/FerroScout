# FerroScout data-flow analysis (0.5.0)

`FS-TAINT-001` adds a deliberately limited taint pass. It is intended to find simple source-to-sink paths that line-based rules may miss.

## Supported input markers

The current source patterns include common web-request properties and a few process/input APIs:

- `req.body`, `req.query`, `req.params`
- `request.args`, `request.form`, `request.GET`, `request.POST`
- `location.search` and `location.hash` (including when passed into `URLSearchParams`)
- `process.argv`, `input()`, `stdin.read...`, and `get_json()`

## Flow model

The pass follows simple assignments such as:

```javascript
const raw = req.query.name;
const alias = raw;
const html = `<p>${alias}</p>`;
element.innerHTML = html;
```

It also follows named relative ES-module imports and named exports across files scanned in the same target:

```javascript
// request.js
export const userQuery = req.query.search;

// view.js
import { userQuery as searchTerm } from './request.js';
const copy = searchTerm;
element.innerHTML = copy;
```

It currently recognizes selected sinks in these groups:

- Dynamic HTML: `innerHTML`, `outerHTML`, `insertAdjacentHTML`, `document.write`
- SQL-like query calls: `.query`, `.execute`, `.raw`, `.raw_sql`
- Shell execution calls: shell APIs such as `os.system`, `child_process.exec`, and `subprocess` calls with `shell=True`
- Filesystem paths: selected `open`, `readFile`, `File::open`, and related calls
- HTTP requests: selected `fetch`, `axios`, `requests`, and client request calls

The pass recognizes a small set of HTML sanitizers (`DOMPurify.sanitize`, `sanitizeHtml`, `escapeHtml`, `escape_html`) only when the assigned or sink expression is a direct sanitizer call. An expression that mixes a sanitized value with another unsanitized tainted value remains tainted. This is still a heuristic: the analyzer does not verify the sanitizer implementation or whether it is appropriate for the exact output context. It does not assume those functions make data safe for SQL, shell, path, or URL contexts.

Static string contents, single-line comments, and block comments are removed before taint source and sink matching. Simple JavaScript template interpolations and Python f-string interpolations are retained so a variable used inside the formatted string can be followed. This is a small lexical approximation, not a complete language lexer.

## Bounds and limitations

- At most 10,000 files and 50,000 analysis facts are retained for data-flow analysis per scan. If the limit is reached, the report includes a scan warning and may omit data-flow paths.
- Cross-file propagation runs for at most 64 rounds.
- Cross-file propagation currently supports named relative ES-module imports. It does not resolve package imports, aliases in re-export declarations, dynamic imports, or CommonJS module graphs.
- The pass does not build ASTs, understand scopes, resolve shadowed variables, follow function arguments/returns, model object properties, or perform interprocedural analysis.
- It does not prove that a value is attacker-controlled or that a sink is exploitable. Parameter binding, path containment, URL allowlists, framework escaping, and authorization logic may require manual review.
- Variable names are treated as simple identifiers. Shadowing and complex expressions can produce missed findings or false positives.
- Sink argument capture is intentionally narrow: most sinks currently expect a simple identifier as their first argument. More complex call expressions may be missed.
- Source and sink patterns are language-neutral heuristics. A match does not establish that the source is remotely attacker-controlled or that an HTTP request runs on a server rather than in a browser.

Treat `FS-TAINT-001` as a focused review lead, not a proof. A scan without findings is not a security guarantee.
