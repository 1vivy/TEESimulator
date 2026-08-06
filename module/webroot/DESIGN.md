# RKA Control Surface Design System

## 0. Research Log

- Embedded references: shortlisted Raycast, Vercel, and Linear; picked Raycast with the operational `taste-skill` lane for its dense, cold, instrument-like hierarchy.
- Lazyweb and Imagen: skipped because this static security control surface has no marketing or raster-art need.
- KernelSU references: adopted the official async `exec` result contract, SpoofUname's post-action refresh and focus-safe forms, and Specter's timeout-safe bridge plus transient snackbar pattern.
- Interaction references: adapted beui.dev's StatefulButton and AnimatedToastStack mechanisms to vanilla CSS: immediate pending state, in-place success/error transition, bounded stacking, and opacity-only reduced motion.

## 1. Atmosphere & Identity

A compact dark operations console organized by the actual setup sequence: understand state, configure the network, run the service, then open advanced maintenance only when needed. Its signature is a double-ring panel surface that separates live facts from actions without claiming that the dashboard itself is the transport.

## 2. Color

`--surface-void #07080a`, `--surface-panel #101111`, `--surface-raised #1b1c1e`, `--text-primary #f9f9f9`, `--text-secondary #cecece`, `--text-muted #9c9c9d`, `--border-default #252829`, `--border-control #74797d`, `--accent-info #55b3ff`, `--status-danger #ff6363`, and `--status-success #6bd69a` are the semantic palette. `--border-accent-hover` and `--border-danger-muted` are the only colored alpha-border variants. White and black alpha variants provide only borders, inset light, shadow, and backdrop depth. Controls use 8px radii, panels use 12px radii, and compact status marks use 4px radii.

## 3. Typography

The Android platform system UI stack is primary so the offline WebView remains native and avoids font-loading delay; ui-monospace is for values. Display is 32px, section headings 20px, tertiary headings 18px, body 16px, compact body 14px, and labels 12px with positive tracking for dark-surface legibility.

## 4. Spacing & Layout

The 4px layout scale uses 8px, 12px, 16px, 24px, and 32px steps. Buttons use 8px by 12px padding. Component measurements additionally use 1px borders, a 3px focus ring, a 44px minimum control height, and intrinsic content widths. The 1120px centered document shell owns scrolling; setup fields use an overflow-safe intrinsic grid and collapse to one readable column below 640px. Advanced maintenance is a disclosure region, not a peer of daily setup.

## 5. Components

### State card
- **Structure**: section, heading, definition list.
- **States**: loading, ready, unavailable, failure.
- **Status semantics**: green means the displayed prerequisite is currently satisfied; red means that prerequisite is blocked or degraded; neutral values are identity, version, transition, or non-applicable metadata. These per-field states do not claim an overall Strong verdict because the WebUI cannot independently verify Google root trust, certificate revocation, attestation security level, certified firmware, bootloader lock, or patch freshness.
- **Accessibility**: labelled live region with text nodes only.

### Fixed action button
- **Structure**: button with a fixed `data-action` enum.
- **States**: default, hover, active, focus-visible, disabled, pending, success, failure.
- **Accessibility**: native keyboard behavior and a visible focus ring.

### Network settings form
- **Structure**: labelled peer IPv4 input, labelled local-interface IPv4 input, fixed read-only port 37373, and one submit button.
- **States**: pristine, locally invalid, pending, saved, rejected, and multi-candidate donor read-only.
- **Scope**: the form edits the current device's single profile only. A donor with candidate-indexed profiles disables the fields and directs the operator to the host CLI rather than applying one address pair to several candidates.
- **Accessibility**: errors are associated with their fields; refresh never overwrites a focused input; the disabled multi-candidate state has a polite textual explanation.

### Action toast
- **Structure**: in-page `role=status` stack with title, bounded detail, and dismiss control.
- **States**: pending, success, failure, unknown; one action updates one toast in place.
- **Lifetime**: pending persists until settlement; results auto-dismiss; only the newest notification remains visible.
- **Accessibility**: polite live updates, text-only content, and no focus theft.

### Session activity
- **Structure**: newest-first list of the current page session's action and outcome.
- **States**: completed outcomes use success semantics; failed outcomes use danger semantics; indeterminate outcomes remain neutral.
- **Storage**: memory only, capped at eight entries; no `localStorage`, `sessionStorage`, or device file.
- **Accessibility**: concise text outcomes; detailed command output is never injected as HTML.

### Protected-action confirmation
- **Structure**: native modal dialog, one-time token output, labelled input, fixed confirm button.
- **States**: closed, awaiting exact token, mismatch, busy, accepted, not sent, outcome unknown.
- **Accessibility**: native focus trapping, explicit heading and label, live operation result.
- **Protected operations**: subsystem recovery, trust rotation, cleanup, candidate-scoped donor RKP provisioning, and candidate synthetic-lease renewal use this confirmation cycle. Candidate identity is part of the confirmed server-side request.

### Role profile workflow
- **Structure**: local JSON file input, Validate control, and Apply validated profile control.
- **States**: empty, loaded, validating, validated, applied, and invalidated-by-file-change.
- **Availability**: loading a parseable file enables only Validate. Apply becomes available only after privileged validation of that exact file-selection revision and is disabled immediately when the input changes or after application.
- **Accessibility**: the native file input and buttons retain keyboard order; availability is represented by native disabled state and the last-operation live region.

## 6. Motion & Interaction

Buttons publish pending state before invoking KernelSU, use 120ms opacity/transform press feedback, and remain independently interruptible. Toasts enter and leave with 160ms opacity/transform transitions and update content without replacing the surface. Reduced motion removes transforms and retains short opacity feedback. Every mutation refreshes status after settlement; bridge requests time out and clean up their callback.

Only one privileged request may be active because every mutation rotates one shared nonce. Pending feedback paints before the native bridge call. A nonzero callback reopens and resynchronizes the session; a timeout is an unknown outcome that locks further mutation until the page is reopened.

## 7. Depth & Surface

Panels and controls use a cool border with inset top light and bottom dark; no decorative imagery or gradients are used.

## 8. Accessibility Constraints & Accepted Debt

WCAG 2.2 AA contrast, 44px targets, keyboard operation, visible focus, input-purpose labels, error association, and reduced motion are required. The fixed skip link is transparent and non-pointer-interactive at rest, then becomes visible when keyboard focus reaches it. Plain-language help distinguishes role profiles from network settings and explains that attestation-root activation is an exceptional signed maintenance operation. Outside KernelSU, the static surface reports its bridge unavailable. Accepted debt: port 37373 is fixed by the current runtime profile and is shown read-only rather than presented as configurable.

## 9. Implementation Boundaries

The dependency-free surface uses ordered classic scripts for Android 10 WebView and `file:` compatibility. `model.js` parses shell output and constructs fixed commands; `bridge.js` owns the three-argument KernelSU callback contract and timeout cleanup; `feedback.js` owns transient buttons, the single live toast region, and memory-only activity; `views.js` renders text-only DOM and form/dialog state; `profile.js` owns local file reading; `app.js` alone owns nonce sequencing, confirmation state, and orchestration. A self-only content security policy prohibits remote code and unsafe inline rendering. Compatibility fallbacks precede `dvh`, `focus-visible`, and flex-gap enhancements.
