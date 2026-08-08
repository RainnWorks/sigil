/**
 * The set of questions this phone has asked the daemon and not yet had answered.
 *
 * **This is a security mechanism, not bookkeeping** (design review F3), and it is
 * small enough to read in one sitting on purpose.
 *
 * The envelope layer no longer gates on the per-direction counter: that check was
 * retired because a restart on either side reset it and genuine, user-approved
 * envelopes were dropped as false replays. What protects the envelope now is a
 * freshness window plus a single-use id set held in RAM on both ends. That set is
 * empty again after any restart, and a phone being killed or backgrounded is
 * routine rather than exceptional.
 *
 * So consider a relay that captures a genuine `LeaseRevokeReply{revoked:true}`.
 * It waits for the app to be killed, which resets the guard. The human reopens
 * the screen and taps revoke. The relay suppresses the outgoing request and
 * delivers the captured reply. Fresh guard, unseen id, valid signature, inside
 * the freshness window, because the message genuinely is genuine. The phone would
 * tell the human the window closed. It is open. That is strictly worse than the
 * "revoke on your Mac" badge this feature replaced, because a badge never lies.
 *
 * The fix is here: a reply is applied only if it names a request THIS process
 * issued and has not yet answered, and claiming it consumes the entry. The map
 * dies with the process, which is precisely what makes the captured reply match
 * nothing in a fresh session. It is single-use at the application layer and
 * stands on its own; it is not belt-and-braces over the envelope guard.
 */

/** What an outstanding request was, so a reply can be applied to something. */
export type OutstandingKind = "list" | "revoke";

export class OutstandingRequests {
  private readonly entries = new Map<string, OutstandingKind>();

  /** Record a question, keyed by the envelope request id it was sent with. */
  issue(requestId: string, kind: OutstandingKind): void {
    this.entries.set(requestId, kind);
  }

  /**
   * Claim the answer to `requestId`. True only when this process issued that
   * exact question, of that exact kind, and has not already answered it; the
   * entry is consumed either way it succeeds, so a second claim always fails.
   *
   * Every false is a drop: an unsolicited reply, a duplicate, a late answer to a
   * question already given up on, a reply of the wrong kind, or a genuine reply
   * captured and replayed into a session that never asked. None of them may move
   * the UI, because none of them is evidence about the window right now.
   */
  claim(requestId: string, kind: OutstandingKind): boolean {
    if (this.entries.get(requestId) !== kind) return false;
    this.entries.delete(requestId);
    return true;
  }

  /** Give up on a question whose reply window has passed. */
  abandon(requestId: string): void {
    this.entries.delete(requestId);
  }

  /** Forget everything, e.g. when the session is torn down. */
  clear(): void {
    this.entries.clear();
  }

  /** How many questions are still open. Diagnostics and tests only. */
  get size(): number {
    return this.entries.size;
  }
}
