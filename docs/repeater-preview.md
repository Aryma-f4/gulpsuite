# Repeater control characters and HTML preview

The request `\n` toggle now paints CRLF (`\r\n`), LF (`\n`), standalone CR
(`\r`) and tab (`\t`) markers over the editable request. Raw bytes, caret and
selection indices are not replaced by literal escape sequences. Adjacent CR
markers receive separate display-only space. The same marker support is wired
into Proxy Intercept. Response displays also handle LF-only messages.

Render now uses a screenshot produced by Chromium rather than the former
text-stripping fallback. Inline CSS, JavaScript and embedded data images render
inside an opaque-origin sandboxed frame with a fresh temporary profile. It does
not share the browser session's cookies. This is a non-interactive visual snapshot,
not an embedded live browser or full-page interactive application.

External HTTP(S) resources are blocked by default. The explicit **Load external
HTTP(S) resources (sends network requests)** checkbox permits loading CSS, scripts
and images from network URLs. Relative resources use the Repeater request URL.
Approval is scoped to the captured response and its base URL: a different response
starts with network access disabled. Opting in sends requests to remote sites.
Forms, direct fetch/XHR and parent navigation stay blocked. No original-session
credentials are replayed.

Wire-chunked HTML and HTML with missing/mismatched Content-Type are recognized.
Actual non-HTML responses should be inspected in Raw or Hex instead of being
misrepresented as HTML.

The renderer uses the bundled browser in packaged installations. Development tests
can set GULPSUITE_TEST_CHROMIUM explicitly. Jobs have a 12-second deadline, at most
two workers, and a four-entry texture cache. Temporary profiles are removed; on
Unix the temporary directory is owner-only.
