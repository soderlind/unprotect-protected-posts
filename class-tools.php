<?php
/**
 * Tools for Protect Protected Posts
 *
 * @package     Soderlind\Plugin\Unprotect
 * @author      Per Soderlind
 */

declare( strict_types = 1 );
namespace Soderlind\Plugin\Unprotect;

if ( ! defined( 'ABSPATH' ) ) {
	wp_die();
}
/**
 * Tools for Protect Protected Posts
 */
class Tools {
	/**
	 * Retrieve the visitor ip address, even it is behind a proxy.
	 *
	 * @author 10up
	 * @link https://github.com/10up/restricted-site-access/blob/72d59c747cc574f9e5ad4a5b43d6b6d6a1ae1b81/restricted_site_access.php
	 * @return string
	 */
	public static function get_client_ip_address() : string {
		$ip      = '';
		$headers = [
			'HTTP_CF_CONNECTING_IP',
			'HTTP_CLIENT_IP',
			'HTTP_X_FORWARDED_FOR',
			'HTTP_X_FORWARDED',
			'HTTP_X_CLUSTER_CLIENT_IP',
			'HTTP_FORWARDED_FOR',
			'HTTP_FORWARDED',
			'REMOTE_ADDR',
		];
		foreach ( $headers as $key ) {

			if ( ! isset( $_SERVER[ $key ] ) ) {
				continue;
			}

			foreach ( explode(
				',',
				sanitize_text_field( wp_unslash( $_SERVER[ $key ] ) )
			) as $ip ) {
				$ip = trim( $ip ); // just to be safe.

				if ( filter_var( $ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE ) !== false ) {
					return $ip;
				}
			}
		}

		return $ip;
	}

	/**
	 * Check if a given ip is in a network.
	 * Source: https://gist.github.com/tott/7684443
	 *
	 * @param  string $ip    IP to check in IPV4 format eg. 127.0.0.1.
	 * @param  string $range IP/CIDR netmask eg. 127.0.0.0/24, also 127.0.0.1 is accepted and /32 assumed.
	 * @return boolean true if the ip is in this range / false if not.
	 */
	public static function ip_in_range( string $ip, string $range ) : bool {
		if ( strpos( $range, '/' ) === false ) {
			$range .= '/32';
		}
		// $range is in IP/CIDR format eg 127.0.0.1/24
		list( $range, $netmask ) = explode( '/', $range, 2 );
		$range_decimal           = ip2long( $range );
		$ip_decimal              = ip2long( $ip );
		$wildcard_decimal        = pow( 2, ( 32 - $netmask ) ) - 1;
		$netmask_decimal         = ~ $wildcard_decimal;
		return ( ( $ip_decimal & $netmask_decimal ) === ( $range_decimal & $netmask_decimal ) );
	}

	/**
	 * Is it a valid IP address? v4/v6 with subnet range.
	 *
	 * @param string $ip_address IP Address to check.
	 *
	 * @return bool True if its a valid IP address.
	 */
	public static function is_ip( $ip_address ) {
		// very basic validation of ranges.
		if ( strpos( $ip_address, '/' ) ) {
			$ip_parts = explode( '/', $ip_address );
			if ( empty( $ip_parts[1] ) || ! is_numeric( $ip_parts[1] ) || strlen( $ip_parts[1] ) > 3 ) {
				return false;
			}
			$ip_address = $ip_parts[0];
		}

		// confirm IP part is a valid IPv6 or IPv4 IP.
		if ( empty( $ip_address ) || ! inet_pton( stripslashes( $ip_address ) ) ) {
			return false;
		}

		return true;
	}
}
