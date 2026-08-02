# RKA Control Surface Design System

## 0. Research Log

- Embedded references: shortlisted Raycast, Vercel, and Linear; picked Raycast with the operational `taste-skill` lane for its dense, cold, instrument-like hierarchy.
- Lazyweb and Imagen: skipped because this static security control surface has no marketing or raster-art need.

## 1. Atmosphere & Identity

A compact dark operations console. Its signature is a double-ring panel surface that separates trusted state from fixed actions without claiming that a dashboard is a transport.

## 2. Color

`--surface-void #07080a`, `--surface-panel #101111`, `--surface-raised #1b1c1e`, `--text-primary #f9f9f9`, `--text-secondary #cecece`, `--text-muted #9c9c9d`, `--border-default #252829`, `--accent-info #55b3ff`, `--status-danger #ff6363`, and `--status-success #6bd69a` are the complete semantic palette. White and black alpha variants provide only borders, inset light, shadow, and backdrop depth.

## 3. Typography

Inter, system-ui, sans-serif is primary; ui-monospace is for values. Display is 32px, section headings 20px, body 16px, and labels 12px with positive tracking for dark-surface legibility.

## 4. Spacing & Layout

The 4px layout scale uses 8px, 12px, 16px, 24px, and 32px steps. Component measurements additionally use 1px borders, a 3px focus ring, a 44px minimum control height, and intrinsic content widths. The 1120px centered document shell owns scrolling; intrinsic cards collapse to one readable column below 640px.

## 5. Components

### State card
- **Structure**: section, heading, definition list.
- **States**: loading, ready, unavailable, failure.
- **Accessibility**: labelled live region with text nodes only.

### Fixed action button
- **Structure**: button with a fixed `data-action` enum.
- **States**: default, hover, active, focus-visible, disabled, busy.
- **Accessibility**: native keyboard behavior and a visible focus ring.

### Protected-action confirmation
- **Structure**: native modal dialog, one-time token output, labelled input, fixed confirm button.
- **States**: closed, awaiting exact token, mismatch, busy, accepted, refused.
- **Accessibility**: native focus trapping, explicit heading and label, live operation result.
- **Protected operations**: subsystem recovery, trust rotation, cleanup, and donor RKP provisioning use this confirmation cycle.

## 6. Motion & Interaction

Buttons use 120ms opacity/transform feedback only; the controller disables a button while its request is outstanding. Reduced motion removes transitions.

## 7. Depth & Surface

Panels and controls use a cool border with inset top light and bottom dark; no decorative imagery or gradients are used.

## 8. Accessibility Constraints & Accepted Debt

WCAG 2.2 AA contrast, 44px targets, keyboard operation, visible focus, and reduced motion are required. Outside KernelSU, the static surface reports its bridge unavailable; Task 26 owns the packaged runtime bridge.
