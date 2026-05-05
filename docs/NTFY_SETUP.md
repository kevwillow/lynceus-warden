# ntfy setup

This walkthrough covers configuring lynceus to deliver alerts to your phone
via ntfy. It's the operational companion to the brief mention in the
[README](../README.md) and the verification step in [SMOKE.md](SMOKE.md#ntfy-reaches-your-phone).

If you're new to ntfy: it's a small, simple notification service. lynceus
publishes alerts to an ntfy topic; your phone subscribes to that topic and
buzzes when alerts arrive. Two pieces, plus a broker in the middle.

## Pick a broker

You have three real options. Skim them all before picking.

### Option A: Use the public ntfy.sh (easiest)

Free. No setup. Works in 60 seconds. Use this if you want to get notifications
working today and don't want to run infrastructure.

The trade-off is privacy. ntfy.sh has no per-topic authentication on the
free tier — anyone who guesses your topic name can subscribe to it and read
your alerts. Topic names are the only secret. Pick a topic name that's
hard to guess: think `lynceus-alerts-7f3a9c2e1b4d`, not `my-alerts`. Use a
random-string generator if you don't trust yourself to pick something
unguessable.

Alert messages pass through ntfy.sh's infrastructure during delivery. They're
not stored long-term (ntfy.sh's default retention is 12 hours), but they
ARE visible to ntfy.sh during transit. Alert content includes MAC addresses
and rule names — privacy-sensitive but not catastrophic.

### Option B: Self-host ntfy (more privacy, more work)

ntfy is a single Go binary. You can run it on the same Pi as lynceus (it's
small enough), or on a separate machine. This keeps alert content within
infrastructure you control during transit.

Real cost: you're now operating a public-facing HTTP server. That means a
domain or dynamic DNS, port forwarding or a tunnel (Cloudflare Tunnel,
Tailscale Funnel, etc.), TLS via Let's Encrypt, and the ongoing maintenance
of all of that. If your home internet drops, alerts stop. If your domain
expires, alerts stop.

One caveat that catches people: even self-hosted ntfy needs to wake your
phone, and phones don't hold persistent connections for battery reasons.
For wake-up, ntfy uses a relay service (the public ntfy.sh's Firebase/APNs
integration on Android and iOS by default). You can opt out of this on
Android with extra setup, but on iOS without paid Apple Developer
credentials, the relay is unavoidable. The alert payload is encrypted
in transit but the relay sees that *some* notification is happening.

Setup guide is at https://docs.ntfy.sh/install/. Out of scope for this doc.

### Option C: Paid ntfy.sh tier (privacy without ops)

ntfy.sh's paid tier (currently around USD $5/month — confirm current pricing
on their site) gives you private topics with proper authentication, longer
retention, and dedicated rate limits. If you want privacy without running
your own server, this is the option. Configuration in lynceus is identical
to Option A, plus a bearer token.

## Configure lynceus

Once you've picked a broker, fill in three fields in your `lynceus.yaml`:

```yaml
ntfy_url: https://ntfy.sh
ntfy_topic: lynceus-alerts-7f3a9c2e1b4d
ntfy_auth_token: null  # only set this for option B with auth or option C
```

For Option A:
- `ntfy_url`: `https://ntfy.sh`
- `ntfy_topic`: your random-string topic name
- `ntfy_auth_token`: leave unset (null)

For Option B with no auth (default ntfy install):
- `ntfy_url`: your self-hosted URL, e.g. `https://ntfy.example.com`
- `ntfy_topic`: a topic name (still pick a hard-to-guess one if your server
  is public-facing)
- `ntfy_auth_token`: leave unset

For Option B with auth or Option C:
- `ntfy_url`: your URL
- `ntfy_topic`: your topic
- `ntfy_auth_token`: your bearer token (generate via ntfy CLI for self-host;
  generate via the dashboard for paid ntfy.sh)

If both `ntfy_url` and `ntfy_topic` are unset, lynceus falls back silently to
the null notifier — no alerts go out, nothing crashes. This is the right
behavior for development and testing. If you intend notifications to work and
they don't, double-check both fields are set in `lynceus.yaml`.

## Install the phone app

Three places to get it:

- iOS: ntfy on the App Store
- Android (recommended): ntfy on the Google Play Store
- Android (preferred for privacy): ntfy on F-Droid

The F-Droid Android build is identical to the Play Store build but built
from source by F-Droid's infrastructure with no Google services dependency.
It can run without Firebase, which means no relay through Google's
infrastructure for wake-ups (more privacy, slightly less battery efficiency).

Once installed:

1. Open the app.
2. Tap "Subscribe to topic" (or "+" depending on platform).
3. For Option A: enter just your topic name. The app defaults to ntfy.sh.
4. For Options B and C: tap "Use another server" first, enter your server
   URL, then enter your topic.
5. For authenticated topics (Option B with auth, Option C): the app will
   prompt for credentials.

You're now subscribed.

## Verify end-to-end

The fastest way to confirm everything works:

1. Make sure lynceus is running (`sudo systemctl status lynceus` shows active)
   or run a one-shot poll (`lynceus --config /etc/lynceus/lynceus.yaml --once`).
2. Watch your phone.
3. If your fixture data (or real-world data) triggers any rule, you should
   see a notification arrive within a few seconds of the rule firing.

If notifications aren't arriving:

- Check `journalctl -u lynceus -n 100` for any "Notifier returned False" or
  "Notifier raised" warnings. These mean lynceus tried to send but the request
  failed.
- For Option A, try `curl -d "test message" https://ntfy.sh/your-topic-name`
  from any machine. If that buzzes your phone, the broker side works and
  the issue is in lynceus's config or output. If that doesn't buzz your
  phone, the broker side is broken (wrong topic name, app not subscribed,
  app misconfigured).
- For Options B and C, try the same `curl` against your URL. If it succeeds
  and the phone buzzes, the broker side works. If the curl fails, the
  broker is unreachable from where lynceus runs (firewall, DNS, TLS).
- Check your phone app: is the topic visible in the subscribed list? Has
  it received any messages historically? Some apps suppress notifications
  if the OS has revoked permission — check Settings → Apps → ntfy →
  Notifications.

## Privacy and security notes

- **Topic names are secrets on Option A.** Treat them like passwords. Don't
  paste your topic into a public bug report. Don't share it casually. If
  it leaks, change it (update `lynceus.yaml`, restart lynceus, resubscribe
  the phone).
- **Alert content is identifying.** Alerts include MAC addresses, rule
  names, and short messages. Anyone who reads your alerts knows which
  surveillance gear (if any) is around your home. This is the threat model
  reason to use Option B or C if you're worried about specific adversaries.
- **No retention beyond ntfy's default.** lynceus does not keep a record of
  notifications it sent — the audit trail is the alerts table in the local
  database, not the notification history. ntfy.sh's default is 12 hours of
  retention. Self-hosted ntfy retention is configurable.
- **Lossy by design.** lynceus treats notification delivery as best-effort.
  If ntfy is unreachable when an alert fires, the alert still lands in the
  database (that's the source of truth) but no notification goes out and
  no retry happens. This is a deliberate v0.2 design — see BACKLOG for
  the queued-delivery work.

## Recommended setup for first deployment

Start with Option A and a randomly-generated topic name. It works in 60
seconds, validates the alert pipeline end-to-end, and tells you whether
you actually want notifications at this granularity before you commit to
running ntfy infrastructure. Most users land on Option A and stay there.

If after a few weeks you want better privacy or your topic names matter,
migrate to Option B or C. The lynceus side of the migration is changing
two lines in `lynceus.yaml` and resubscribing the phone. lynceus does not
care which broker it's pointed at.
