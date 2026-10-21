# Beavizor

Beavizor is a local-first beauty-services listing and appointment app. The backend uses Ruby, WEBrick, SQLite, and OpenSSL. It has no external gem dependencies in the supplied environment.

## Requirements

- Ruby 2.6 or newer
- The `sqlite3` and `webrick` gems

Check the runtime and start the app:

```sh
ruby -v
ruby -e 'require "webrick"; require "sqlite3"; puts "Dependencies ready"'
ruby server.rb
```

Open `http://127.0.0.1:8000`. Do not open the HTML file directly; sign-in and all saved data require the server.

## Local accounts and email

For local testing, the default `EMAIL_MODE=console` prints verification and password-reset links in the server terminal instead of sending email. Create an account in the app, copy the `DEVELOPMENT EMAIL` verification URL from that terminal, and open it in your browser.

For real email, copy `.env.example` to `.env`, configure a real SMTP host, sender, and provider-issued app password, and set `EMAIL_MODE=smtp`. Verification and reset links expire after one hour and can only be used once. Never put real credentials in the ZIP or share them in chat.

## Administrator and listings

Before starting the server, set `BEAVIZOR_ADMIN_EMAIL` and a unique `BEAVIZOR_ADMIN_PASSWORD` of at least 10 characters in `.env`. Regular users cannot grant themselves admin permissions. Admins can review submitted service listings and publish or reject them; only published listings appear in public search.

Users can submit a listing with a title, category, description, price, city, and optional HTTPS photo URL. Each submission waits for administrator review.

## Storage and limitations

- User accounts, bookings, listing submissions, messages, and sessions are stored in `beavizor.sqlite3` next to the server.
- Passwords are stored as salted PBKDF2-HMAC-SHA256 hashes. Sessions use HttpOnly cookies.
- Email verification is required before sign-in.
- There are no seeded provider profiles or work photos. Search stays empty until verified provider listings are added and approved.
- Payment collection and live provider/customer chat are not implemented. The current message feature saves notes to the signed-in user's account; it does not deliver them to a provider.

The bundled WEBrick server is for local development only. Do not expose it directly to the public internet. A public launch needs HTTPS, production hosting, SMTP configuration, backups, and a security review.

## Prepared test deployment

See TEST_YAYINI.md for test access and limitations. The included render.yaml uses the free Ruby runtime with automatic deployments disabled. Runtime testing has not yet completed. Never use real customer data in this temporary test environment.
