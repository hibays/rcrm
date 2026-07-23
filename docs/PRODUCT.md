# Product

## Register

product

Mixed: primary register is product (the app UI), but a future marketing/landing surface is in scope. Current work defaults to product register.

## Users

Adult content collectors who manage large encrypted local media libraries. Privacy-focused power users, desktop-first (Windows/Linux/Mac) with Android as secondary platform. They operate in personal/dim environments — late-night browsing, private spaces. They value speed, smoothness, and discretion.

The job to be done: browse, preview, and play a personal encrypted media collection with zero friction and zero plaintext disk writes.

## Product Purpose

RCrm lets people with encrypted media libraries browse them as fluidly as a streaming service. Encrypted ChaCha20+Argon2id folders are served through a local read-only WebDAV server, decrypted on-the-fly, and rendered through a Flutter GUI. No plaintext ever touches disk. The experience should feel like a premium streaming platform — not a file manager.

Success looks like: a user opens the app, enters their password, and instantly sees a beautiful media library they can browse, play, and enjoy — without ever thinking about encryption.

## Brand Personality

Bold, unapologetic, smooth. Three words.

The bold orange/yellow accent on deep dark background is a deliberate choice — not an accident to be corrected. Own it. The brand doesn't apologize for what it is. It's not corporate, not sterile, not safe. It's confident, direct, and polished.

Voice: direct, no euphemisms. Tone: smooth and confident, not brash or crude.

## Anti-references

- Generic SaaS/enterprise UI — no clean white/blue, no admin-panel tropes, no corporate minimalism
- Sterile media players (VLC, Plex default) — no boring playback chrome
- Overdesigned "dark luxury" that forgets it's a browsing tool

## Design Principles

1. **Content is king.** The media is the star. Chrome fades away — auto-hiding controls, dark backgrounds, no visual noise competing with videos and images.

2. **Daring and unapologetic.** The orange accent on deep dark is a bold move. Own it. No apologetic pastels, no safe neutrals, no gradient-text decor. If it feels like it belongs on a different product, it doesn't belong here.

3. **Zero friction browsing.** Fast scanning, hover previews, gesture-driven controls, instant transitions. Performance should feel like direct manipulation — not like a network app. The 200ms hover delay and 2s idle fade are intentional; latency is designed, not tolerated.

4. **Privacy obsessiveness.** Encryption is the product's reason to exist. The interface conveys security through confidence — not through paranoia (no warning icons, no "encrypted!" badges). The user's media is protected, and the UI never makes them think about it.

## Accessibility & Inclusion

Used primarily in dark, personal environments. Standard WCAG AA serves as baseline (4.5:1 text contrast, focus indicators) but readability in dim/low-light conditions is the practical goal. Reduced-motion support via `prefers-reduced-motion` for all animations. No screen-reader-specific accommodations needed at this stage; standard platform semantics where they're free.
