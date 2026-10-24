// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Zeknod OÜ
//
// A copy of the ZEKNOP reference implementation of the canonical content
// specification, carried by the JavaScript example so that the example counts
// the same bytes as the service that signed the message. Apart from this header
// and the substitutions recorded with the copy, nothing in this file was changed.

// The shared canonicalisation contract (canonical-content.md).
// One implementation, one place to change when the specification changes.
export * from './base.mjs';
export * from './digest.mjs';
export * from './headers.mjs';
export * from './mime.mjs';
export * from './envelope.mjs';
export * from './message.mjs';
