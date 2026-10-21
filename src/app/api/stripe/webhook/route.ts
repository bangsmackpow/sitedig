import type { NextRequest } from 'next/server';
import { createHash } from 'node:crypto';
import { getWebConfig } from '@/shared/config';
import { ensureInitialized } from '@/server/bootstrap';
import { errorJson, json, PayloadTooLargeError, readTextLimited } from '@/server/http';
import { getStripe, handleStripeEvent } from '@/server/billing/stripe';
import { getDb } from '@/server/db';

export const dynamic = 'force-dynamic';

export async function POST(req: NextRequest): Promise<Response> {
  await ensureInitialized();
  const cfg = getWebConfig();
  if (!cfg.stripe.configured) return errorJson('Stripe is not configured.', 500, 'not_configured');

  const signature = req.headers.get('stripe-signature');
  if (!signature) return errorJson('Missing Stripe signature.', 400, 'bad_signature');

  let raw: string;
  try {
    raw = await readTextLimited(req, 1024 * 1024);
  } catch (e) {
    if (e instanceof PayloadTooLargeError) return errorJson('Webhook payload is too large.', 413, 'payload_too_large');
    throw e;
  }
  let event;
  try {
    event = getStripe(cfg).webhooks.constructEvent(raw, signature, cfg.stripe.webhookSecret);
  } catch {
    return errorJson('Invalid Stripe signature.', 400, 'invalid_signature');
  }

  const db = getDb();
  const existing = db.prepare('SELECT processing_error FROM webhook_events WHERE stripe_event_id = ?').get(event.id) as
    | { processing_error: string | null }
    | undefined;
  if (existing && existing.processing_error === null) {
    return json({ received: true, idempotent: true });
  }
  // A previous attempt failed. Remove the tombstone so Stripe's retry can run
  // the handler again instead of being permanently treated as processed.
  if (existing) {
    db.prepare('DELETE FROM webhook_events WHERE stripe_event_id = ?').run(event.id);
  }

  const payloadHash = createHash('sha256').update(raw).digest('hex');
  try {
    await handleStripeEvent(event);
    db.prepare('INSERT INTO webhook_events (stripe_event_id, event_type, payload_hash, processed_at) VALUES (?, ?, ?, ?)').run(
      event.id,
      event.type,
      payloadHash,
      new Date().toISOString(),
    );
  } catch (e) {
    db.prepare('INSERT INTO webhook_events (stripe_event_id, event_type, payload_hash, processed_at, processing_error) VALUES (?, ?, ?, ?, ?)').run(
      event.id,
      event.type,
      payloadHash,
      new Date().toISOString(),
      (e as Error).message,
    );
    throw e; // let Stripe retry
  }

  return json({ received: true, idempotent: false });
}
