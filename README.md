# OAuth

The two halves of an OAuth 2.0 authorization-code round trip that providers leave to you: a PKCE pair (RFC 7636, S256) and a signed `state` bound to a cookie in the browser that started the trip, so a callback is only honoured where it began.

## Why

Every "Sign in with GitHub", "Connect Discord" or "Link your account" button is the same round trip: send the browser to the provider with a `state`, take the `code` back at a callback, swap it for a token. The provider checks its half. Yours is the `state`, and the usual hand-rolled one gets at least one of these wrong:

- **A signed state is still a bearer value.** If it is not tied to the browser, an attacker starts a trip, stops at the callback, and sends the link to a victim, whose browser finishes the attacker's sign-in (login CSRF). The fix is a second half that never leaves the browser: a cookie.
- **The state goes through somebody else's logs.** It travels through the provider, its logs and the address bar, so anything in it — an order's token, a user id — leaks. Here it carries only a nonce and a hash of what the trip is for.
- **PKCE is optional, so it is forgotten.** A code that leaks on the way back is worth nothing without the verifier. `State::start()` makes the pair itself; the verifier only ever sits in the cookie.

## Features

- 🔐 **PKCE** — RFC 7636 S256 only (`plain` protects nothing), verifiers from `random_bytes`, checked against the RFC's alphabet and length, tested against Appendix B.
- 🍪 **Cookie-bound state** — two signed halves that must agree: same nonce, and the state's hash must be the hash of the value in the cookie.
- 🙈 **Nothing private in the URL** — the bound value, the verifier and your own data ride in the HttpOnly cookie.
- ⏱️ **Short-lived** — both halves expire together (15 minutes by default).
- 🧱 **Separate namespaces** — the cookie is signed under `<namespace>-cookie`, so neither half can stand in for the other.

## Requirements

PHP 8.5+, [`sugarcommerce/signed-tokens`](https://github.com/sugarcommerce/signed-tokens).

## Installation

```bash
composer require sugarcommerce/oauth
```

## Usage

```php
use SugarCommerce\OAuth\{Pkce, State};
use SugarCommerce\SignedTokens\TokenSigner;

$state = new State( new TokenSigner( $secret ), 'github-join', 900 );

// Starting: what the trip acts for, plus anything the callback needs.
$out = $state->start( $download_token, array( 'back' => 'order' ) );

$url = 'https://github.com/login/oauth/authorize?' . http_build_query( array(
    'client_id'             => $client_id,
    'redirect_uri'          => $callback,
    'state'                 => $out->state,
    'code_challenge'        => $out->challenge,
    'code_challenge_method' => Pkce::METHOD,
) );

// Set $out->cookie: HttpOnly, Secure, SameSite=Lax, Path=/callback.

// The callback.
$trip = $state->resume( $_GET['state'] ?? '', $_COOKIE['trip'] ?? '' );

if ( null === $trip ) {
    // Not started in this browser, expired, or forged. Refuse.
}

$token = $provider->exchange( $_GET['code'], $callback, $trip->verifier );
$trip->bind;          // the download token
$trip->get( 'back' ); // 'order'
```

Clear the cookie in the callback whatever happens.

SameSite must be `Lax`, not `Strict`: the way back is a top-level navigation from the provider's site, which Strict would send without the cookie.

### PKCE on its own

```php
[ 'verifier' => $verifier, 'challenge' => $challenge ] = Pkce::pair();

Pkce::challenge( $verifier );   // base64url(sha256(verifier))
Pkce::valid( $verifier );       // 43–128 of A-Z a-z 0-9 - . _ ~
```

## What it does not do

- **Single use.** The trip cookie is cleared on the way back and the provider's code is single-use, which covers the round trip. A state that must be spent exactly once across browsers (an app install that has no cookie) needs a store — see `sugarcommerce/sqlite`'s `Cache`.
- **Set the cookie.** Nothing here sets headers; build it with your framework's cookie helper.

## Testing

```bash
composer install
composer test
```

21 tests — the RFC 7636 Appendix B vector, verifier alphabet and length bounds, the round trip, a state without its cookie (login CSRF), halves of two trips, a state moved to another bound value, swapped halves, another namespace, expiry, tampering, reserved keys, and the `#[\NoDiscard]` on `resume()`.

## License

GPL-2.0-or-later
