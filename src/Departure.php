<?php
/**
 * What starting a trip hands back.
 *
 * @package   SugarCommerce\OAuth
 * @copyright Copyright (c) 2026, ArrayPress Limited
 * @license   GPL-2.0-or-later
 * @since     1.0.0
 */

declare( strict_types=1 );

namespace SugarCommerce\OAuth;

/**
 * Class Departure
 *
 * Three values with three destinations, kept apart by name so they are not
 * mixed up: `state` and `challenge` go to the provider in the authorize
 * URL; `cookie` goes to the browser and nowhere else. The PKCE verifier is
 * not here at all — it is inside the cookie, which is the point.
 *
 * @since 1.0.0
 */
final readonly class Departure {

	/**
	 * Bundle the three values. Only {@see State::start()} makes one.
	 *
	 * @since 1.0.0
	 *
	 * @param string $state     For the authorize URL's `state`.
	 * @param string $cookie    The value for the trip cookie.
	 * @param string $challenge For `code_challenge`, with `code_challenge_method`
	 *                          {@see Pkce::METHOD}.
	 */
	public function __construct(
		public string $state,
		#[\SensitiveParameter] public string $cookie,
		public string $challenge,
	) {}
}
