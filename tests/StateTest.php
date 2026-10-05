<?php
/**
 * A state bound to the browser that started the trip.
 *
 * @package   SugarCommerce\OAuth
 * @copyright Copyright (c) 2026, ArrayPress Limited
 * @license   GPL-2.0-or-later
 */

declare( strict_types=1 );

namespace SugarCommerce\OAuth\Tests;

use PHPUnit\Framework\TestCase;
use SugarCommerce\OAuth\{Pkce, State, Trip};
use SugarCommerce\SignedTokens\{Base64Url, TokenSigner};

/**
 * Class StateTest
 */
final class StateTest extends TestCase {

	private const string SECRET = 'a-secret-that-is-at-least-32-bytes-long!';

	private function state( ?int $now = null, string $namespace = 'github-join' ): State {
		return new State( new TokenSigner( self::SECRET, timestamp: $now ), $namespace, 900 );
	}

	/* ─── The round trip ────────────────────────────────────────────── */

	public function test_a_trip_comes_back_with_its_value_its_verifier_and_its_data(): void {
		$state = $this->state();
		$out   = $state->start( 'download-token', array( 'b' => 'order', 's' => 1 ) );
		$back  = $state->resume( $out->state, $out->cookie );

		$this->assertInstanceOf( Trip::class, $back );
		$this->assertSame( 'download-token', $back->bind );
		$this->assertSame( $out->challenge, Pkce::challenge( $back->verifier ), 'The verifier is the one the challenge was made from.' );
		$this->assertSame( 'order', $back->get( 'b' ) );
		$this->assertSame( 1, $back->get( 's' ) );
		$this->assertNull( $back->get( 'missing' ) );
		$this->assertSame( array( 'b' => 'order', 's' => 1 ), $back->data, 'The state\'s own keys are not the caller\'s.' );
	}

	/**
	 * Nothing private goes through the provider: not the bound value, not
	 * the verifier.
	 */
	public function test_the_state_carries_neither_the_value_nor_the_verifier(): void {
		$out     = $this->state()->start( 'download-token' );
		$payload = (string) Base64Url::decode( explode( '.', $out->state )[0] );
		$back    = $this->state()->resume( $out->state, $out->cookie );

		$this->assertStringNotContainsString( 'download-token', $payload );
		$this->assertStringNotContainsString( (string) $back?->verifier, $payload );
		$this->assertSame( array( 'n', 'o' ), array_keys( (array) json_decode( $payload, true ) ) );
	}

	/* ─── Refusals ──────────────────────────────────────────────────── */

	/**
	 * Login CSRF: somebody else's state, without their cookie, is nothing.
	 */
	public function test_a_state_without_its_cookie_is_refused(): void {
		$state = $this->state();
		$out   = $state->start( 'tok' );

		$this->assertNull( $state->resume( $out->state, '' ) );
		$this->assertNull( $state->resume( '', $out->cookie ) );
	}

	public function test_halves_of_two_trips_do_not_make_one(): void {
		$state = $this->state();
		$one   = $state->start( 'tok' );
		$two   = $state->start( 'tok' );

		$this->assertNull( $state->resume( $one->state, $two->cookie ), 'Different nonces.' );
	}

	public function test_a_state_for_one_value_does_not_open_another(): void {
		$signer = new TokenSigner( self::SECRET );
		$state  = new State( $signer, 'github-join' );
		$mine   = $state->start( 'mine' );

		// Forge a cookie for another value with the same nonce: the signer
		// is ours in this test, which an attacker's would not be, so this
		// shows the binding is checked even when everything else agrees.
		$nonce   = json_decode( (string) Base64Url::decode( explode( '.', $mine->state )[0] ), true )['n'];
		$theirs  = $signer->sign( 'github-join-cookie', array( 'n' => $nonce, 't' => 'theirs', 'v' => str_repeat( 'v', 43 ) ), 900 );

		$this->assertNull( $state->resume( $mine->state, $theirs ) );
	}

	public function test_the_halves_cannot_stand_in_for_each_other(): void {
		$state = $this->state();
		$out   = $state->start( 'tok' );

		$this->assertNull( $state->resume( $out->cookie, $out->state ) );
		$this->assertNull( $state->resume( $out->state, $out->state ) );
	}

	public function test_another_namespace_is_refused(): void {
		$out = $this->state( namespace: 'discord-join' )->start( 'tok' );

		$this->assertNull( $this->state()->resume( $out->state, $out->cookie ) );
	}

	public function test_an_expired_trip_is_refused(): void {
		$out = $this->state( 1_000_000 )->start( 'tok' );

		$this->assertNotNull( $this->state( 1_000_000 + 899 )->resume( $out->state, $out->cookie ) );
		$this->assertNull( $this->state( 1_000_000 + 901 )->resume( $out->state, $out->cookie ) );
	}

	public function test_a_tampered_half_is_refused(): void {
		$state = $this->state();
		$out   = $state->start( 'tok' );

		$this->assertNull( $state->resume( $out->state . 'x', $out->cookie ) );
		$this->assertNull( $state->resume( $out->state, 'forged' ) );
	}

	/* ─── Misuse ────────────────────────────────────────────────────── */

	public function test_the_states_own_keys_cannot_be_overwritten(): void {
		$this->expectException( \InvalidArgumentException::class );

		$this->state()->start( 'tok', array( 'v' => 'my own verifier' ) );
	}

	public function test_a_state_lives_at_least_a_second(): void {
		$this->expectException( \InvalidArgumentException::class );

		new State( new TokenSigner( self::SECRET ), 'x', 0 );
	}

	/* ─── Results that must be checked ──────────────────────────────── */

	public function test_resume_must_be_checked(): void {
		$attributes = ( new \ReflectionMethod( State::class, 'resume' ) )->getAttributes( \NoDiscard::class );

		$this->assertCount( 1, $attributes );
		$this->assertNotSame( '', $attributes[0]->newInstance()->message );
	}
}
