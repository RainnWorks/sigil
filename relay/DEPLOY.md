# Deploying the relay to Cloudflare

This is the exact runbook for the publisher's shared instance (the Worker +
Durable Object variant, `src/index.ts`). For self-hosting instead, see the
"Self-host with Docker" section in `README.md`.

## What you need before starting

- A Cloudflare account.
- `wrangler` authenticated against it (`npx wrangler login`, interactive,
  one-time; opens a browser).
- The APNs `.p8` signing key text. It lives in 1Password: Engineering vault,
  item `bs6pgv35lpazziews7zsvd6y7e` ("Latch APNs Auth Key, Key ID
  5PCK76SDBA"). Get the document contents (not just the item fields).
- Optional: a domain already added as a zone in the same Cloudflare account,
  if you want the relay reachable at that domain (e.g. `relay.rainn.works`)
  instead of the default `*.workers.dev` subdomain.

Nothing else is required. There is no database, no KV namespace, no queue to
provision: the relay's only state is a Durable Object's own in-memory buffer,
declared entirely in `wrangler.jsonc`.

## Steps

```sh
cd relay
npm install

# One-time: authenticate wrangler against your Cloudflare account.
npx wrangler login

# One-time per environment: the APNs signing key, as a secret (never a var,
# never committed). Paste the .p8 PEM text when prompted.
npx wrangler secret put APNS_KEY_P8

# Deploy.
npx wrangler deploy
```

`wrangler deploy` prints the URL it published to (either
`sigil-relay.<your-subdomain>.workers.dev`, or your custom domain if routes
are configured, see below).

## Custom domain (optional)

Requires the domain to already be a zone in the same Cloudflare account.
Either:

- **Dashboard**: Workers & Pages -> `sigil-relay` -> Settings -> Triggers ->
  Custom Domains -> Add, e.g. `relay.rainn.works`. Cloudflare provisions the
  DNS record and certificate automatically.
- **Config file**: uncomment and fill in the `routes` block already sketched
  in `wrangler.jsonc`, then `npx wrangler deploy` again:
  ```jsonc
  "routes": [{ "pattern": "relay.rainn.works", "custom_domain": true }]
  ```

## Verify

```sh
# Liveness.
curl https://<your-worker-or-domain>/health
# -> {"ok":true,"service":"sigil-relay"}

# Deposit/drain round trip (any 64-lowercase-hex string is a valid mailbox id
# for this smoke test; it does not need to correspond to a real pairing).
ID=$(python3 -c "import secrets;print(secrets.token_hex(32))")
curl -X POST "https://<your-worker-or-domain>/mailbox/$ID/to-phone" \
  -d '{"env":"smoke-test"}'
curl "https://<your-worker-or-domain>/mailbox/$ID/to-phone"
# -> {"envelopes":["smoke-test"]}
```

To verify the push doorbell for real, deposit against a mailbox id from an
actual paired phone and include its real `pushToken`:

```sh
curl -X POST "https://<your-worker-or-domain>/mailbox/<real-mailbox-id>/to-phone" \
  -d '{"env":"smoke-test","pushToken":"<the-phone's-real-apns-token>","platform":"apns"}'
```

and confirm the phone receives a generic "Approval requested" notification.
A missing or wrong `APNS_KEY_P8` fails open (logged, the deposit still
200s); check `npx wrangler tail` for a `push:` log line if the notification
doesn't arrive.

## Rollback / redeploy

Every `wrangler deploy` is a new version; roll back from the dashboard
(Workers & Pages -> `sigil-relay` -> Deployments -> pick a previous version
-> Rollback) or redeploy the previous commit. There is no data migration
concern: the relay carries no persisted state to migrate or roll back.

## What still needs a human with Cloudflare access

Everything above that isn't `git`: the account itself, `wrangler login`,
`wrangler secret put APNS_KEY_P8` with the real key, and (if wanted) owning
the domain used for the custom route. None of this can be prepared further
from the repository; the config here is deploy-ready and waiting on those
steps.
