<?php
/**
 * Name: Unprotect Protected Posts
 *
 * @package     Soderlind\Plugin\Unprotect
 * @author      Per Soderlind
 * @copyright   2021 Per Soderlind
 * @license     GPL-2.0+
 *
 * @wordpress-plugin
 * Plugin Name: Unprotect Protected Posts
 * Plugin URI: https://github.com/soderlind/unprotect-protected-posts
 * GitHub Plugin URI: https://github.com/soderlind/unprotect-protected-posts
 * Description: Give direct access to logged-in users and/or users from a defined IP-address to the protected posts.
 * Version:     1.0.1
 * Author:      Per Soderlind
 * Author URI:  https://soderlind.no
 * Text Domain: unprotect-protected-posts
 * License:     GPL-2.0+
 * License URI: http://www.gnu.org/licenses/gpl-2.0.txt
 */

declare( strict_types = 1 );
namespace Soderlind\Plugin\Unprotect;

if ( ! defined( 'ABSPATH' ) ) {
	wp_die();
}

require_once __DIR__ . '/class-tools.php';

if ( is_admin() ) {
	load_plugin_textdomain( 'unprotect-protected-posts', false, dirname( plugin_basename( __FILE__ ) ) . '/languages' );
	require_once __DIR__ . '/class-options.php';
	$unprotect_protected_posts = new Options();
}


/**
 * Filters whether a post requires the user to supply a password.
 *
 * @param bool     $required Whether the user needs to supply a password. True if password has not been
 * provided or is incorrect, false if password has been supplied or is not required.
 *
 * @param \WP_Post $post     Post object.
 * @return bool Whether the user needs to supply a password. True if password has not been
 * provided or is incorrect, false if password has been supplied or is not required.
 */
add_filter(
	'post_password_required',
	function( bool $required, \WP_Post $post ) : bool {

		$options = get_option( 'unprotect_protected_posts', false );
		if ( ! $options ) {
			return $required;
		}

		if ( is_user_logged_in() && isset( $options['give_access'] ) && 'yes' === $options['give_access'] ) {
			return false;
		}

		$allowed_ips = ( isset( $options['ip_addresses'] ) ) ? explode( "\n", $options['ip_addresses'] ) : [];
		$allowed_ips = array_map( 'trim', $allowed_ips );
		if ( count( $allowed_ips ) > 0 ) {
			$remote_ip = Tools::get_client_ip_address();
			foreach ( $allowed_ips as $line ) {
				if ( Tools::ip_in_range( $remote_ip, $line ) ) {
					return false;
				}
			}
		}

		return $required;
	},
	10,
	2
);
