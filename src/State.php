<?php
/**
 * An OAuth state bound to the browser that started the trip.
 *
 * @package   SugarCommerce\OAuth
 * @copyright Copyright (c) 2026, ArrayPress Limited
 * @license   GPL-2.0-or-later
 * @since     1.0.0
 */

declare( strict_types=1 );

namespace SugarCommerce\OAuth;

use SugarCommerce\SignedTokens\{Token, TokenSigner};

/**
 * Class State
 *
 * An authorization-code trip has two halves that must meet again on the
 * way back. The `state` goes out through the provider and comes back in
 * the callback's query string; the cookie stays in the browser that
 * started it. A callback is honoured only when both are ours, unexpired,
 * and agree.
 *
 * What that prevents:
 *
 * - **Login CSRF.** A signed state alone is a bearer value: an attacker
 *   starts a trip, stops at the callback, and sends the link to a victim,
 *   whose browser then finishes the attacker's sign-in. Without the
 *   victim's cookie the state is refused.
 * - **Leaking what the trip is for.** The state carries only a nonce and a
 *   keyed hash of the value it is bound to (an order's download token, a
 *   user id), never the value, so nothing private passes through the
 *   provider, its logs or the address bar. The hash is keyed with the PKCE
 *   verifier, which only the cookie holds, so a guessable value such as a
 *   user id cannot be recovered from the state by hashing candidates. The value, the PKCE verifier and anything
 *   else the callback needs ride in the cookie.
 * - **Moving a state between trips.** The nonce must match, and the hash
 *   in the state must be the hash of the value in the cookie.
 * - **A code without its verifier.** start() makes the PKCE pair itself,
 *   so a caller cannot forget it; the verifier is only ever in the cookie.
 *
 * The cookie is signed under the namespace plus "-cookie", so neither half
 * can stand in for the other. Set it HttpOnly, Secure, SameSite=Lax (the
 * way back is a top-level navigation from the provider, which Strict
 * would drop), scoped to the callback path; clear it in the callback.
 *
 * @since 1.0.0
 */
final readonly class State {

	/**
	 * Payload keys this class uses, so a caller's own cannot overwrite them.
	 */
	private const array RESERVED = array( 'n', 't', 'v' );

	/**
	 * Set up trips of one kind.
	 *
	 * @since 1.0.0
	 *
	 * @param TokenSigner $signer    Signs both halves.
	 * @param string      $namespace What the trip is, e.g. `github-join`.
	 *                               Letters, digits, `-`, `_`, `.`; at most
	 *                               57 characters, leaving room for
	 *                               "-cookie".
	 * @param int         $ttl       Seconds either half lives: long enough
	 *                               to sign in at the provider, no longer.
	 *
	 * @throws \InvalidArgumentException On a non-positive lifetime.
	 */
	public function __construct(
		private TokenSigner $signer,
		private string $namespace,
		public int $ttl = 900,
	) {
		if ( $ttl < 1 ) {
			throw new \InvalidArgumentException( 'A state lives at least one second.' );
		}
	}

	/**
	 * Begin a trip.
	 *
	 * @since 1.0.0
	 *
	 * @param string                         $bind    What the trip acts for:
	 *                                                returned by resume(),
	 *                                                never sent to the
	 *                                                provider.
	 * @param array<string, string|int|bool> $private Anything else the
	 *                                                callback needs, kept in
	 *                                                the cookie. Not the keys
	 *                                                n, t or v.
	 *
	 * @return Departure The state and challenge to send, and the cookie value.
	 *
	 * @throws \InvalidArgumentException When $private uses a reserved key.
	 * @throws \Random\RandomException   When the CSPRNG is unavailable.
	 */
	public function start( #[\SensitiveParameter] string $bind, array $private = array() ): Departure {
		$clash = array_intersect( array_keys( $private ), self::RESERVED );

		if ( array() !== $clash ) {
			throw new \InvalidArgumentException( 'The keys ' . implode( ', ', self::RESERVED ) . ' are the state\'s own.' );
		}

		$pkce  = Pkce::pair();
		$nonce = bin2hex( random_bytes( 16 ) );

		return new Departure(
			$this->signer->sign( $this->namespace, array( 'n' => $nonce, 'o' => $this->binding( $bind, $pkce['verifier'] ) ), $this->ttl ),
			$this->signer->sign( $this->cookie_namespace(), array( 'n' => $nonce, 't' => $bind, 'v' => $pkce['verifier'] ) + $private, $this->ttl ),
			$pkce['challenge'],
		);
	}

	/**
	 * Match a callback's state with the cookie set when it began.
	 *
	 * @since 1.0.0
	 *
	 * @param string $state  The callback's `state`.
	 * @param string $cookie The cookie value from start().
	 *
	 * @return Trip|null Null when either is missing, forged or expired, or
	 *                   they do not belong together.
	 */
	#[\NoDiscard( 'Null means the callback did not start in this browser: refuse it.' )]
	public function resume( string $state, #[\SensitiveParameter] string $cookie ): ?Trip {
		if ( '' === $state || '' === $cookie ) {
			return null;
		}

		$from = $this->signer->inspect( $this->namespace, $state );
		$trip = $this->signer->inspect( $this->cookie_namespace(), $cookie );

		if ( ! $from instanceof Token || ! $trip instanceof Token ) {
			return null;
		}

		$bind     = (string) $trip->get( 't' );
		$nonce    = (string) $trip->get( 'n' );
		$verifier = (string) $trip->get( 'v' );

		if ( '' === $bind || '' === $nonce || '' === $verifier || ! hash_equals( $nonce, (string) $from->get( 'n' ) ) || ! hash_equals( $this->binding( $bind, $verifier ), (string) $from->get( 'o' ) ) ) {
			return null;
		}

		return new Trip( $bind, $verifier, array_diff_key( $trip->payload, array_flip( self::RESERVED ) ) );
	}

	/**
	 * What ties a state to its bound value without carrying the value.
	 *
	 * An HMAC keyed with the trip's PKCE verifier: the verifier lives only
	 * in the cookie, so whoever sees the state (the provider, its logs, the
	 * address bar) cannot test guesses of the bound value against it.
	 *
	 * @since 1.1.0
	 *
	 * @param string $bind     The bound value.
	 * @param string $verifier The trip's PKCE verifier, used as the key.
	 *
	 * @return string 32 hex characters.
	 */
	private function binding( #[\SensitiveParameter] string $bind, #[\SensitiveParameter] string $verifier ): string {
		return substr( hash_hmac( 'sha256', $this->namespace . '|' . $bind, $verifier ), 0, 32 );
	}

	/**
	 * The cookie's namespace.
	 *
	 * @since 1.0.0
	 *
	 * @return string The trip's namespace plus "-cookie".
	 */
	private function cookie_namespace(): string {
		return $this->namespace . '-cookie';
	}
}
