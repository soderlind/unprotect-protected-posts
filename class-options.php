<?php
/**
 * Option page for Unprotect Protected Posts
 *
 * @package     Soderlind\Plugin\Unprotect
 */

declare( strict_types = 1 );
namespace Soderlind\Plugin\Unprotect;

if ( ! defined( 'ABSPATH' ) ) {
	wp_die();
}

/**
 *  Option page for Unprotect Protected Posts
 */
class Options {
	/**
	 * Options array
	 *
	 * @var array
	 */
	private $options;

	/**
	 * Constructor
	 */
	public function __construct() {
		add_action( 'admin_menu', [ $this, 'add_plugin_page' ] );
		add_action( 'admin_init', [ $this, 'page_init' ] );
	}

	/**
	 * Add options page
	 */
	public function add_plugin_page() {
		add_options_page(
			'Unprotect Protected Posts',
			'Unprotect Posts',
			'manage_options',
			'unprotect-protected-posts',
			[ $this, 'create_admin_page' ]
		);
	}

	/**
	 * Options page callback
	 */
	public function create_admin_page() {
		$this->options = get_option( 'unprotect_protected_posts' );

		$html  = '<div class="wrap">';
		$html .= '<h1>';
		$html .= __( 'Unprotect Protected Posts', 'unprotect-protected-posts' );
		$html .= '</h1>';
		$html .= '<p>';
		$html .= __( 'Give direct access to logged - in users and/or users from a defined IP - address to the <a href="https://wordpress.org/support/article/using-password-protection/#password-protected-posts">protected posts</a>.', 'unprotect-protected-posts' );
		$html .= '</p>';
		$html .= '<form method ="post" action="options.php">';
		echo $html; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
					settings_fields( 'unprotect_protected_posts_group' );
					do_settings_sections( 'unprotect - protected - posts - admin' );
					submit_button();
		$html  = '</form>';
		$html .= '</div>';
		echo $html; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
	}

	/**
	 * Register and add settings
	 *
	 * @return void
	 */
	public function page_init() {
		register_setting(
			'unprotect_protected_posts_group',
			'unprotect_protected_posts',
			[ $this, 'sanitize' ]
		);

		add_settings_section(
			'unprotect_protected_posts_section',
			'',
			[ $this, 'section_info' ],
			'unprotect - protected - posts - admin'
		);

		add_settings_field(
			'give_access',
			__( 'Allow logged in user ? ', 'unprotect - protected - posts' ),
			[ $this, 'give_access_callback' ],
			'unprotect - protected - posts - admin',
			'unprotect_protected_posts_section',
			[
				'label_for'   => 'give_access',
				'description' => 'Give access to logged in users',
			]
		);

		add_settings_field(
			'ip_addresses',
			__( 'Add IP - address', 'unprotect - protected - posts' ),
			[ $this, 'ip_address_callback' ],
			'unprotect - protected - posts - admin',
			'unprotect_protected_posts_section',
			[
				'label_for'   => 'ip_addresses',
				'description' => __( 'One per line . Also accepts / subnet - mask, as in 1.2.3.4 / 32.', 'unprotect - protected - posts' ) . ' ' . __( 'Your IP - Address is : ', 'unprotect - protected - posts' ) . Tools::get_client_ip_address(),
			]
		);
	}

	/**
	 * Sanitize each setting field as needed
	 *
	 * @param array $input Contains all settings fields as array keys.
	 *
	 * @return array
	 */
	public function sanitize( array $input ) : array {

		if ( ! is_array( $input ) && get_option( 'unprotect_protected_posts' ) === $input ) {
			return $input;
		}

		$type            = 'updated';
		$sanitary_values = [];
		if ( isset( $input['give_access'] ) ) {
			$sanitary_values['give_access'] = $input['give_access'];
		}

		if ( isset( $input['ip_addresses'] ) ) {
			$sanitary_values['ip_addresses'] = $input['ip_addresses'];
			if ( ! empty( $sanitary_values['ip_addresses'] ) ) {
				$ip_adresses = explode( "\n", $sanitary_values['ip_addresses'] );
				$ip_adresses = array_map( 'trim', $ip_adresses );
				foreach ( $ip_adresses as $ip_address ) {
					if ( '' === $ip_address ) {
						continue;
					}
					if ( ! Tools::is_ip( $ip_address ) ) {
						$type = 'error';
						// translators: %s is the IP-address.
						$message = sprintf( __( '%s is not a valid IP - address', 'unprotect-protected-posts' ), esc_html( $ip_address ) );
						add_settings_error(
							'unprotect_protected_posts',
							esc_attr( 'settings_updated' ),
							$message,
							$type
						);
						$sanitary_values = get_option( 'unprotect_protected_posts' ); // Use the current database value. This will cancel saving the option.
						break;
					}
				}
			}
		}

		return $sanitary_values;
	}

	/**
	 * Echo the settings section info.
	 */
	public function section_info() {

	}

	/**
	 * Display give_access field
	 *
	 * @param array $args Arguments from add_settings_field().
	 *
	 * @return void
	 */
	public function give_access_callback( array $args ) : void {

		$checked = ( isset( $this->options['give_access'] ) ) ? $this->options['give_access'] : 'no';

		$html  = '';
		$html .= '<fieldset>';
		$html .= '<label for="give_access-0"><input type = "radio" id="give_access-0" name="unprotect_protected_posts[give_access]" value="yes" ' . checked( $checked, 'yes', false ) . '>' . __( 'Yes' ) . '</label><br>';
		$html .= ' <label for="give_access-1"><input type="radio" id="give_access-1" name="unprotect_protected_posts[give_access]" value="no" ' . checked( $checked, 'no', false ) . '>' . __( 'No' ) . ' </label><br>';
		if ( isset( $args['description'] ) && '' !== $args['description'] ) {
			$html .= ' <p class="description">' . esc_html( $args['description'] ) . '</p>';
		}
		$html .= ' </fieldset>';
		echo $html; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
	}

	/**
	 * Display ip_address field
	 *
	 * @param array $args Arguments from add_settings_field().
	 */
	public function ip_address_callback( array $args ) : void {

		$html  = '';
		$html .= '<fieldset>';
		$html .= sprintf(
			'<textarea class="large-text" rows="5" name="unprotect_protected_posts[ip_addresses]" id="ip_addresses">%s</textarea>',
			isset( $this->options['ip_addresses'] ) ? esc_attr( $this->options['ip_addresses'] ) : ''
		);
		if ( isset( $args['description'] ) && '' !== $args['description'] ) {
			$html .= ' <p class="description"> ' . esc_html( $args['description'] ) . '</p>';
		}
		$html .= '</fieldset>';
		echo $html; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
	}

}
