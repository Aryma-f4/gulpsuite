# Gulpsuite macOS KVO lifecycle patch

Source: crates.io `accesskit_macos` 0.22.2, pinned by `engine/Cargo.lock`.
Upstream: https://github.com/AccessKit/accesskit
License: MIT OR Apache-2.0; original source headers and both licenses retained.

Only `SubclassingAdapter::drop` differs from the published crate. Before restoring
the view's original Objective-C class, inspect the public NSObject
`observationInfo` property. If observers remain, preserve the subclass and its
associated adapter state until the native view is deallocated. This prevents
AppKit's Touch Bar finder from losing its `nextResponder` KVO registration.
Unobserved views keep the original detach/reattach behavior. Accessibility stays
available; no AppKit exception is swallowed and no private Touch Bar API is used.

Reproduction and native integration check (requires an interactive macOS session):

```
CARGO_PROFILE_DEV_DEBUG=0 CARGO_INCREMENTAL=0 cargo run --example native_history_smoke
```

Without the patch, adding a `nextResponder` observer, dropping the adapter, then
removing that observer aborts with a foreign Objective-C exception (exit 134).
With the patch, the observer lifecycle and 80 native UI frames switching between
Dashboard and populated HTTP history complete successfully (exit 0). The example
also checks repeated adapter detach/reattach on an unobserved view.

The association may outlive the Rust adapter when KVO observers exist. Its lifetime
is bounded by the NSView; Objective-C releases it on view deallocation. Creating a
second adapter on the same still-observed view is not supported by this patch;
eframe creates one adapter per native view.
