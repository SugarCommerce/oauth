<?php
/**
 * Proof Key for Code Exchange (RFC 7636).
 *
 * @package   SugarCommerce\OAuth
 * @copyright Copyright (c) 2026, ArrayPress Limited
 * @license   GPL-2.0-or-later
 * @since     1.0.0
 */

declare( strict_types=1 );

namespace SugarCommerce\OAuth;

use SugarCommerce\SignedTokens\Base64Url;

/**
 * Class Pkce
 *
 * A code that leaks on the way back — a browser history, a referrer, a
 * proxy log, another app registered for the same redirect — is worth
 * nothing without the verifier, which never leaves the server that started
 * the trip. That is the whole of PKCE, and it is worth having even for a
 * confidential client with a secret, which is why OAuth 2.1 makes it
 * mandatory for everybody.
 *
 * The two mistakes it prevents: a verifier made from something other than
 * a CSPRNG (or too short to be one, below the RFC's 43 characters), and
 * the `plain` method, which sends the verifier itself through the browser
 * and so protects nothing. Only S256 is offered.
 *
 * @since 1.0.0
 */
final readonly class Pkce {

	/**
	 * The only challenge method worth sending.
	 */
	public const string METHOD = 'S256';

	/**
	 * A fresh verifier and the challenge made from it.
	 *
	 * The verifier is 32 random bytes, base64url: 43 characters, the
	 * shortest RFC 7636 allows and 256 bits, which is all it needs.
	 *
	 * @since 1.0.0
	 *
	 * @return array{verifier: string, challenge: string}
	 *
	 * @throws \Random\RandomException When the CSPRNG is unavailable.
	 */
	public static function pair(): array {
		$verifier = Base64Url::encode( random_bytes( 32 ) );

		return array( 'verifier' => $verifier, 'challenge' => self::challenge( $verifier ) );
	}

	/**
	 * The S256 challenge for a verifier.
	 *
	 * @since 1.0.0
	 *
	 * @param string $verifier The verifier.
	 *
	 * @return string base64url(sha256(verifier)), unpadded.
	 *
	 * @throws \InvalidArgumentException When the verifier is not one RFC 7636
	 *                                   allows: 43 to 128 of A-Z a-z 0-9 - . _ ~
	 */
	public static function challenge( #[\SensitiveParameter] string $verifier ): string {
		if ( ! self::valid( $verifier ) ) {
			throw new \InvalidArgumentException( 'A PKCE verifier is 43 to 128 characters of A-Z, a-z, 0-9, "-", ".", "_" and "~".' );
		}

		return Base64Url::encode( hash( 'sha256', $verifier, true ) );
	}

	/**
	 * Whether a string is a verifier RFC 7636 allows.
	 *
	 * @since 1.0.0
	 *
	 * @param string $verifier Candidate.
	 *
	 * @return bool
	 */
	public static function valid( #[\SensitiveParameter] string $verifier ): bool {
		return 1 === preg_match( '/^[A-Za-z0-9\-._~]{43,128}$/', $verifier );
	}
}
