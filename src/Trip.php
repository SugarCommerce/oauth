<?php
/**
 * A trip that came back to the browser it started in.
 *
 * @package   SugarCommerce\OAuth
 * @copyright Copyright (c) 2026, ArrayPress Limited
 * @license   GPL-2.0-or-later
 * @since     1.0.0
 */

declare( strict_types=1 );

namespace SugarCommerce\OAuth;

/**
 * Class Trip
 *
 * Only ever made by {@see State::resume()} once both halves have been
 * verified and matched, so holding one means the callback belongs to this
 * browser. It does not mean the provider agreed: exchange the code, with
 * the verifier, before acting.
 *
 * @since 1.0.0
 */
final readonly class Trip {

	/**
	 * Bundle a matched trip. Only {@see State::resume()} makes one.
	 *
	 * @since 1.0.0
	 *
	 * @param string                         $bind     The value the trip was
	 *                                                 started for.
	 * @param string                         $verifier The PKCE verifier, for
	 *                                                 the token exchange.
	 * @param array<string, string|int|bool> $data     The caller's own values
	 *                                                 from start().
	 */
	public function __construct(
		#[\SensitiveParameter] public string $bind,
		#[\SensitiveParameter] public string $verifier,
		public array $data = array(),
	) {}

	/**
	 * One of the caller's own values.
	 *
	 * @since 1.0.0
	 *
	 * @param string               $key     Name given to start().
	 * @param string|int|bool|null $default Returned when absent.
	 *
	 * @return string|int|bool|null
	 */
	public function get( string $key, string|int|bool|null $default = null ): string|int|bool|null {
		return $this->data[ $key ] ?? $default;
	}
}
