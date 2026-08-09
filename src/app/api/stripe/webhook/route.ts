import type { NextRequest } from 'next/server';
import { createHash } from 'node:crypto';
import { getWebConfig } from '@/shared/config';
import { ensureInitialized } from '@/server/bootstrap';
import { errorJson, json } from '@/server/http';
import { getStripe, handleStripeEvent } from '@/server/billing/stripe';
import { getDb } from '@/server/db';

export const dynamic = 'force-dynamic';

export async function POST(req: NextRequest): Promise<Response> {
  await ensureInitialized();
  const cfg = getWebConfig();
  if (!cfg.stripe.configured) return errorJson('Stripe is not configured.', 500, 'not_configured');

  const signature = req.headers.get('stripe-signature');
  if (!signature) return errorJson('Missing Stripe signature.', 400, 'bad_signature');

  const raw = await req.text();
  let event;
  try {
    event = getStripe(cfg).webhooks.constructEvent(raw, signature, cfg.stripe.webhookSecret);
  } catch {
    return errorJson('Invalid Stripe signature.', 400, 'invalid_signature');
  }

  const db = getDb();
  const existing = db.prepare('SELECT id FROM webhook_events WHERE stripe_event_id = ?').get(event.id);
  if (existing) {
    return json({ received: true, idempotent: true });
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
