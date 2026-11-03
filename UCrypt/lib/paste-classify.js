/**
 * UCrypt — R132 §2.2 — LAW 0.47: THE PASTE-GUIDANCE LAW (the CEO's S2).
 *
 * WHAT THE KING SAW: the manual transfer's two raw code boxes accepted any
 * paste in any order — a wrong-order paste landed silently (or as an opaque
 * error), and the only recovery was re-pasting "Copy my signal" on BOTH
 * devices. The order-dependence was real but the UI never taught it.
 *
 * THE LAW: every pasted signal is CLASSIFIED ON PASTE — with the typed
 * identity and the typed next action. A wrong-order paste is never a silent
 * dead end — it is a guided correction. The same classifier rides the Direct
 * Share inputs.
 *
 * The classes (every one carries its guidance key — the copy lives in i18n):
 *   empty            — nothing pasted (the caller keeps its own hint).
 *   not-a-record     — the text is not any UCrypt signal: say what IS valid.
 *   own-signal       — the record's `from` is THIS device: "This is YOUR
 *                      signal — the other device needs it. Copy it and send
 *                      it to them." (the R107 self-truth, generalized to
 *                      every record kind).
 *   presence         — the other device's discovery signal (leg 1).
 *   offer            — an invitation (a file offer): the receiver pastes it.
 *   answer           — a reply: only meaningful on a device that SENT an
 *                      offer and still awaits the answer (the page refines
 *                      with its own state — reply-without-offer is the law's
 *                      named class).
 *   ice              — a connection detail mid-handshake.
 *   cancel/complete/decline — terminal notices riding an existing transfer.
 *   join             — a join request: belongs on the ORIGIN device's window.
 *   sync-offer / sync-answer — the continuous-sync signals (the Cloud Sync
 *                      surfaces own them).
 *   share-invitation — 'UCRYPT-SHARE1:' — the Direct Share invitation.
 *   share-reply      — 'UCRYPT-SHARE1R:' — the Direct Share reply.
 *   share-qr-part    — 'UCRYPT-SHAREQ1:' — one QR chunk of a split code.
 *   pickup-notice    — 'UCRYPT-PICKUP1:' — a held pickup's notice.
 *
 * PURE — no DOM, no chrome.*, no imports: the battery pins every class, the
 * self-detection, and the prefix sniffing. The wire prefixes are pinned
 * constants (0.15) — mirrored here by value so the classifier stays
 * dependency-free (the separation laws 0.27 hold: this module never touches
 * the vault, the chain, or any credential).
 */

export const SHARE_INVITE_PREFIX = 'UCRYPT-SHARE1:'
export const SHARE_REPLY_PREFIX = 'UCRYPT-SHARE1R:'
export const SHARE_QR_PREFIX = 'UCRYPT-SHAREQ1:'
export const PICKUP_NOTICE_PREFIX = 'UCRYPT-PICKUP1:'

export const PASTE_CLASSES = {
  EMPTY: 'empty',
  NOT_A_RECORD: 'not-a-record',
  OWN_SIGNAL: 'own-signal',
  PRESENCE: 'presence',
  OFFER: 'offer',
  ANSWER: 'answer',
  ICE: 'ice',
  CANCEL: 'cancel',
  COMPLETE: 'complete',
  DECLINE: 'decline',
  JOIN: 'join',
  SYNC_OFFER: 'sync-offer',
  SYNC_ANSWER: 'sync-answer',
  SHARE_INVITATION: 'share-invitation',
  SHARE_REPLY: 'share-reply',
  SHARE_QR_PART: 'share-qr-part',
  PICKUP_NOTICE: 'pickup-notice',
}

/** The sealed-record kinds the transfer plane puts on the wire (mailbox.js). */
const RECORD_KINDS = new Set([
  'offer', 'answer', 'ice', 'cancel', 'complete', 'decline', 'presence', 'join',
  'sync-offer', 'sync-answer',
])

/**
 * Structural sniff of a pasted transfer-plane signal: base64(JSON envelope).
 * The envelope is NOT encrypted (only the payload is) — kind/from/to are
 * readable without any key. Returns null when the text is not one.
 */
export function sniffTransferRecord(text) {
  try {
    const json = atob(String(text || '').trim())
    const rec = JSON.parse(json)
    if (!rec || typeof rec !== 'object') return null
    if (typeof rec.kind !== 'string' || !RECORD_KINDS.has(rec.kind)) return null
    if (typeof rec.from !== 'string' || !rec.from) return null
    return { kind: rec.kind, from: rec.from, to: typeof rec.to === 'string' ? rec.to : '' }
  } catch { return null }
}

/**
 * THE CLASSIFIER (law 0.47). Classify ANY pasted signal.
 * @param {string} text the pasted text (trimmed by the caller or here)
 * @param {{selfId?:string}} ctx this device's id ('' → self-detection off)
 * @returns {{cls:string, self:boolean, kind:string, guidanceKey:string, guidanceFallback:string}}
 *          cls is a PASTE_CLASSES value; guidanceKey is the i18n key carrying
 *          the typed next action (0.29 — the fix lives with the diagnosis).
 */
export function classifyPastedSignal(text, ctx = {}) {
  const t = String(text || '').trim()
  if (!t) {
    return { cls: PASTE_CLASSES.EMPTY, self: false, kind: '', guidanceKey: 'pasteGuideEmpty', guidanceFallback: 'Paste a signal from the other device.' }
  }
  const selfId = String(ctx.selfId || '')
  const rec = sniffTransferRecord(t)
  if (rec) {
    const self = !!selfId && rec.from === selfId
    if (self) {
      return {
        cls: PASTE_CLASSES.OWN_SIGNAL, self: true, kind: rec.kind,
        guidanceKey: 'pasteGuideOwnSignal',
        guidanceFallback: 'This is YOUR signal — the other device needs it, not this one. Copy it from this device ("Copy my signal") and paste it there.',
      }
    }
    const guide = {
      presence: ['pasteGuidePresence', 'This is THEIR signal — press "Open" to learn that device, then let them see you (copy your signal back).'],
      offer: ['pasteGuideOffer', 'This is an INVITATION — press "Open" to receive the offered transfer.'],
      answer: ['pasteGuideAnswer', 'This is a REPLY code — it completes a transfer this device SENT. If you never sent an offer, complete Step 1 first (copy your signal to them).'],
      ice: ['pasteGuideIce', 'This is a connection detail for a transfer in progress — press "Open" to apply it.'],
      cancel: ['pasteGuideCancel', 'This is a cancellation notice — press "Open" to mark that transfer cancelled.'],
      complete: ['pasteGuideComplete', 'This is a delivery confirmation — press "Open" to mark the transfer Delivered.'],
      decline: ['pasteGuideDecline', 'This is a decline notice — the other device refused the transfer.'],
      join: ['pasteGuideJoin', 'This is a JOIN request — it belongs on the ORIGIN device (the one that created the sync code), pasted under "Paste the join signal here".'],
      'sync-offer': ['pasteGuideSyncOffer', 'This is a continuous-sync signal — paste it on the Cloud Sync tab ("No cloud connecting the devices? Paste the join signal here").'],
      'sync-answer': ['pasteGuideSyncAnswer', 'This is a continuous-sync answer — paste it on the device that created the sync offer (Cloud Sync tab).'],
    }[rec.kind] || ['pasteGuideUnknown', 'This is a UCrypt signal, but this surface cannot say which kind — check which window produced it.']
    return { cls: rec.kind, self: false, kind: rec.kind, guidanceKey: guide[0], guidanceFallback: guide[1] }
  }
  if (t.startsWith(SHARE_INVITE_PREFIX)) {
    return { cls: PASTE_CLASSES.SHARE_INVITATION, self: false, kind: 'share-invitation', guidanceKey: 'pasteGuideShareInvite', guidanceFallback: 'This is a Direct Share INVITATION — it goes in "Have a share code?" (the receiver\'s paste box), then press "Paste a share invitation".' }
  }
  if (t.startsWith(SHARE_REPLY_PREFIX)) {
    return { cls: PASTE_CLASSES.SHARE_REPLY, self: false, kind: 'share-reply', guidanceKey: 'pasteGuideShareReply', guidanceFallback: 'This is a Direct Share REPLY — it belongs on the SENDER\'s device ("Their reply code"), then press "Connect reply".' }
  }
  if (t.startsWith(SHARE_QR_PREFIX)) {
    return { cls: PASTE_CLASSES.SHARE_QR_PART, self: false, kind: 'share-qr-part', guidanceKey: 'pasteGuideShareQr', guidanceFallback: 'This is ONE PART of a scanned share code — assemble all parts (or use "Scan their QR" again) before continuing.' }
  }
  if (t.startsWith(PICKUP_NOTICE_PREFIX)) {
    return { cls: PASTE_CLASSES.PICKUP_NOTICE, self: false, kind: 'pickup-notice', guidanceKey: 'pasteGuidePickup', guidanceFallback: 'This is a pickup notice — paste it in "Have a share code?" on the receiver\'s device to pick the file up.' }
  }
  return { cls: PASTE_CLASSES.NOT_A_RECORD, self: false, kind: '', guidanceKey: 'pasteGuideNotRecord', guidanceFallback: 'This doesn\'t look like a UCrypt signal — copy the whole code (it starts with a base64 block or "UCRYPT-…") and paste it again.' }
}

/**
 * The role-aware refinement the law demands on the TRANSFER's two boxes:
 * the classifier's static class + THIS page's live state → the typed
 * correction. The page's state (awaiting a reply / awaiting an offer) turns
 * the two wrong-order classes the CEO named into their guided corrections:
 *   - a reply lands here but this device never sent an offer →
 *     reply-without-offer ("complete Step 1 first").
 *   - an invitation lands here while this device AWAITS a reply →
 *     invitation-when-expecting-reply ("you need THEIR reply").
 * @param {{cls:string,self:boolean}} c the classifyPastedSignal result
 * @param {{awaitingReply:boolean, awaitingOffer:boolean}} page
 */
export function refineForManualBox(c, page = {}) {
  if (c.cls === PASTE_CLASSES.ANSWER && page.awaitingReply === false) {
    return { ...c, guidanceKey: 'pasteGuideReplyNoOffer', guidanceFallback: 'This is a reply code, but you haven\'t created an offer yet — complete Step 1 first: press "Copy my signal" and send it to the other device.' }
  }
  if (c.cls === PASTE_CLASSES.OFFER && page.awaitingReply === true) {
    return { ...c, guidanceKey: 'pasteGuideInviteExpectingReply', guidanceFallback: 'This looks like an invitation — but this device is the SENDER here: you need THEIR reply, not another invitation.' }
  }
  return c
}

/**
 * The SHARE boxes' refinement (the same classifier rides Direct Share):
 * the invitation box wants an invitation; the reply box wants a reply —
 * a right code in the right box CONFIRMS (the typed identity is also the
 * "you're on track" signal), a right code in the wrong box names its home.
 * @param {{cls:string}} c the classifyPastedSignal result
 * @param {{box:'invitation'|'reply'}} box
 */
export function refineForShareBox(c, box = 'invitation') {
  // The callers pass the shape { box: 'invitation' | 'reply' }; a bare
  // string is honored too (the battery calls both shapes).
  const b = (box && typeof box === 'object') ? String(box.box || 'invitation') : String(box || 'invitation')
  const wantInvite = b === 'invitation'
  if (wantInvite && c.cls === PASTE_CLASSES.SHARE_INVITATION) {
    return { ...c, guidanceKey: 'pasteGuideShareInviteOk', guidanceFallback: 'This is an invitation — press "Paste a share invitation" to read it.' }
  }
  if (wantInvite && c.cls === PASTE_CLASSES.SHARE_REPLY) {
    return { ...c, guidanceKey: 'pasteGuideShareReplyWrongBox', guidanceFallback: 'This is a REPLY code — it belongs on the SENDER\'s device ("Their reply code" on the share card), not here.' }
  }
  if (!wantInvite && c.cls === PASTE_CLASSES.SHARE_REPLY) {
    return { ...c, guidanceKey: 'pasteGuideShareReplyOk', guidanceFallback: 'This is their reply — press "Connect reply" to open the connection.' }
  }
  if (!wantInvite && c.cls === PASTE_CLASSES.SHARE_INVITATION) {
    return { ...c, guidanceKey: 'pasteGuideShareInviteWrongBox', guidanceFallback: 'This is an INVITATION — it belongs on the RECEIVER\'s device ("Have a share code?"), not here.' }
  }
  return c
}
