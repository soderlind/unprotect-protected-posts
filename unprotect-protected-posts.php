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
 * Version:     1.0.0
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
require_once __DIR__ . '/class-options.php';

if ( is_admin() ) {
	$unprotect_protected_posts = new Options();
}

$options = get_option( 'unprotect_protected_posts', false );
if ( ! $options ) {
	return;
}

add_action(
	'init',
	function() use ( $options ) {

		if ( is_user_logged_in() && isset( $options['give_access'] ) && 'yes' === $options['give_access'] ) {
			add_filter( 'post_password_required', '__return_false' );
		} else {
			$allowed_ips = ( isset( $options['ip_addresses'] ) ) ? explode( "\n", $options['ip_addresses'] ) : [];
			$allowed_ips = array_map( 'trim', $allowed_ips );
			if ( count( $allowed_ips ) > 0 ) {
				$remote_ip = Tools::get_client_ip_address();
				foreach ( $allowed_ips as $line ) {
					if ( Tools::ip_in_range( $remote_ip, $line ) ) {
						add_filter( 'post_password_required', '__return_false' );
						return;
					}
				}
			}
		}
	}
);
