<?php
/**
 * PKCE.
 *
 * @package   SugarCommerce\OAuth
 * @copyright Copyright (c) 2026, ArrayPress Limited
 * @license   GPL-2.0-or-later
 */

declare( strict_types=1 );

namespace SugarCommerce\OAuth\Tests;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SugarCommerce\OAuth\Pkce;

/**
 * Class PkceTest
 */
final class PkceTest extends TestCase {

	/* ─── The RFC's own example ─────────────────────────────────────── */

	/**
	 * RFC 7636 Appendix B.
	 */
	public function test_the_challenge_matches_the_rfc_example(): void {
		$this->assertSame( 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM', Pkce::challenge( 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk' ) );
	}

	/* ─── Pairs ─────────────────────────────────────────────────────── */

	public function test_a_pair_is_a_fresh_verifier_and_its_challenge(): void {
		$one = Pkce::pair();
		$two = Pkce::pair();

		$this->assertSame( 43, strlen( $one['verifier'] ) );
		$this->assertTrue( Pkce::valid( $one['verifier'] ) );
		$this->assertSame( Pkce::challenge( $one['verifier'] ), $one['challenge'] );
		$this->assertNotSame( $one['verifier'], $two['verifier'] );
		$this->assertStringNotContainsString( '=', $one['challenge'], 'Unpadded, as the RFC says.' );
	}

	public function test_only_s256_is_offered(): void {
		$this->assertSame( 'S256', Pkce::METHOD );
	}

	/* ─── Verifiers the RFC does not allow ──────────────────────────── */

	/**
	 * @return array<string, array{string}>
	 */
	public static function bad_verifiers(): array {
		return array(
			'too short'  => array( str_repeat( 'a', 42 ) ),
			'too long'   => array( str_repeat( 'a', 129 ) ),
			'a space'    => array( str_repeat( 'a', 42 ) . ' ' ),
			'a plus'     => array( str_repeat( 'a', 42 ) . '+' ),
			'empty'      => array( '' ),
		);
	}

	#[DataProvider( 'bad_verifiers' )]
	public function test_a_verifier_outside_the_rfc_is_refused( string $verifier ): void {
		$this->assertFalse( Pkce::valid( $verifier ) );

		$this->expectException( \InvalidArgumentException::class );
		Pkce::challenge( $verifier );
	}

	public function test_the_unreserved_punctuation_is_allowed(): void {
		$this->assertTrue( Pkce::valid( str_repeat( 'a', 39 ) . '-._~' ) );
		$this->assertTrue( Pkce::valid( str_repeat( 'Z', 128 ) ) );
	}
}
