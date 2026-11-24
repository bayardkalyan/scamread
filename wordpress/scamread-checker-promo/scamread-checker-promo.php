<?php
/**
 * Plugin Name:       ScamRead Checker Promo
 * Plugin URI:        https://github.com/bayardkalyan/scamread
 * Description:       A small, dismissible pop-up that points visitors to the free ScamRead scam checker (app.scamread.com). Settings → ScamRead Checker.
 * Version:           1.0.0
 * Requires at least: 6.0
 * Requires PHP:      7.4
 * Author:            ScamRead
 * Author URI:        https://scamread.com/
 * License:           MIT
 * Text Domain:       scamread-checker-promo
 */

defined( 'ABSPATH' ) || exit;

const SRCP_VERSION = '1.0.0';
const SRCP_OPTION  = 'srcp_settings';

function srcp_defaults() {
	return array(
		'enabled'   => 1,
		'delay'     => 6,
		'hide_days' => 7,
		'url'       => 'https://app.scamread.com/',
	);
}

function srcp_settings() {
	$saved = get_option( SRCP_OPTION, array() );
	return wp_parse_args( is_array( $saved ) ? $saved : array(), srcp_defaults() );
}

/* ---------------------------------------------------------------------------
 * Front end: markup, styles and script are printed once in the footer.
 * Nothing is loaded from other sites and nothing is stored on the server; the
 * "don't show again" choice lives in the visitor's own browser.
 * ------------------------------------------------------------------------ */

add_action( 'wp_footer', 'srcp_render', 50 );

function srcp_render() {
	$s = srcp_settings();
	if ( empty( $s['enabled'] ) || is_admin() || is_feed() || is_embed() || is_customize_preview() ) {
		return;
	}

	$url = add_query_arg(
		array(
			'utm_source'   => 'scamread.com',
			'utm_medium'   => 'popup',
			'utm_campaign' => 'scam_checker',
		),
		$s['url']
	);
	$config = array(
		'delay'    => max( 0, (int) $s['delay'] ) * 1000,
		'hideDays' => max( 1, (int) $s['hide_days'] ),
	);
	?>
<div id="srcp" class="srcp" role="dialog" aria-modal="false" aria-labelledby="srcp-title" hidden>
	<button type="button" class="srcp-close" aria-label="<?php esc_attr_e( 'Close', 'scamread-checker-promo' ); ?>">&times;</button>
	<div class="srcp-head">
		<svg class="srcp-eye" viewBox="0 0 48 30" aria-hidden="true" focusable="false"><path d="M2 15C9 5 16 2 24 2s15 3 22 13C39 25 32 28 24 28S9 25 2 15Z" fill="#0B1117" stroke="#40E2D6" stroke-width="3" stroke-linejoin="round"/><circle cx="24" cy="15" r="8" fill="none" stroke="#40E2D6" stroke-width="2"/><circle cx="24" cy="15" r="4" fill="#FF4656"/></svg>
		<span class="srcp-label"><?php esc_html_e( 'Free scam checker', 'scamread-checker-promo' ); ?></span>
	</div>
	<p id="srcp-title" class="srcp-title"><?php esc_html_e( 'Got a suspicious message?', 'scamread-checker-promo' ); ?></p>
	<p class="srcp-text"><?php esc_html_e( 'Paste it into our free checker and see the warning signs in seconds. Nothing is saved.', 'scamread-checker-promo' ); ?></p>
	<a class="srcp-cta" href="<?php echo esc_url( $url ); ?>"><?php esc_html_e( 'Check a message', 'scamread-checker-promo' ); ?> <span aria-hidden="true">&rarr;</span></a>
</div>
<style id="srcp-css">
.srcp{position:fixed;right:20px;bottom:20px;z-index:99990;width:340px;max-width:calc(100vw - 24px);box-sizing:border-box;padding:18px 18px 16px;border-radius:16px;background:#0D1319;border:1px solid #40E2D6;box-shadow:0 18px 50px rgba(0,0,0,.45),0 0 0 4px rgba(64,226,214,.08);color:#E8EEF2;font-family:Inter,ui-sans-serif,system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;line-height:1.5;opacity:0;transform:translateY(16px);transition:opacity .25s ease,transform .25s ease}
.srcp.srcp-in{opacity:1;transform:none}
.srcp[hidden]{display:none!important}
.srcp *{box-sizing:border-box}
.srcp-head{display:flex;align-items:center;gap:10px;margin:0 28px 10px 0}
.srcp-eye{width:34px;height:22px;flex:none}
.srcp-label{font-family:"JetBrains Mono",ui-monospace,monospace;font-size:11.5px;letter-spacing:.12em;text-transform:uppercase;color:#40E2D6}
.srcp-title{margin:0 0 4px!important;font-size:18px;font-weight:800;color:#fff;line-height:1.3}
.srcp-text{margin:0 0 14px!important;font-size:14.5px;color:#B8C3CA}
.srcp .srcp-cta{display:flex;align-items:center;justify-content:center;gap:8px;min-height:44px;border-radius:10px;background:#40E2D6;color:#06090C!important;font-weight:800;font-size:15px;text-decoration:none!important;transition:transform .15s}
.srcp .srcp-cta:hover{transform:translateY(-1px)}
.srcp-close{position:absolute;top:8px;right:8px;width:32px;height:32px;padding:0;border:0;border-radius:8px;background:transparent;color:#808E98;font-size:22px;line-height:32px;cursor:pointer}
.srcp-close:hover,.srcp-close:focus-visible{color:#fff;background:#1A2A30}
.srcp a:focus-visible,.srcp button:focus-visible{outline:2px solid #40E2D6;outline-offset:2px}
@media (max-width:560px){.srcp{left:12px;right:12px;bottom:12px;width:auto;padding:16px}}
@media (prefers-reduced-motion:reduce){.srcp{transition:none}}
</style>
<script id="srcp-js">
(function () {
	var cfg = <?php echo wp_json_encode( $config ); ?>;
	var box = document.getElementById('srcp');
	if (!box) return;
	var KEY = 'srcp_hide_until', SEEN = 'srcp_seen';
	function store(type) { try { return window[type]; } catch (e) { return null; } }
	var ls = store('localStorage'), ss = store('sessionStorage');
	function get(s, k) { try { return s ? s.getItem(k) : null; } catch (e) { return null; } }
	function set(s, k, v) { try { if (s) s.setItem(k, v); } catch (e) {} }
	function track(name) { if (typeof window.gtag === 'function') window.gtag('event', name, { event_category: 'scam_checker' }); }
	function hideFor(days) { set(ls, KEY, String(Date.now() + days * 864e5)); }

	if (Number(get(ls, KEY) || 0) > Date.now()) return;
	if (get(ss, SEEN)) return;
	if (/(^|\.)app\.scamread\.com$/.test((document.referrer.split('/')[2] || ''))) return;

	function close(days) {
		box.classList.remove('srcp-in');
		setTimeout(function () { box.hidden = true; }, 250);
		hideFor(days);
		document.removeEventListener('keydown', onKey);
	}
	function onKey(e) { if (e.key === 'Escape') { track('scam_checker_popup_close'); close(cfg.hideDays); } }

	box.querySelector('.srcp-close').addEventListener('click', function () { track('scam_checker_popup_close'); close(cfg.hideDays); });
	box.querySelector('.srcp-cta').addEventListener('click', function () { track('scam_checker_popup_click'); hideFor(30); });

	setTimeout(function () {
		box.hidden = false;
		set(ss, SEEN, '1');
		requestAnimationFrame(function () { requestAnimationFrame(function () { box.classList.add('srcp-in'); }); });
		document.addEventListener('keydown', onKey);
		track('scam_checker_popup_view');
	}, cfg.delay);
})();
</script>
	<?php
}

/* ---------------------------------------------------------------------------
 * Settings → ScamRead Checker
 * ------------------------------------------------------------------------ */

add_action( 'admin_menu', 'srcp_admin_menu' );
add_action( 'admin_init', 'srcp_admin_init' );
add_filter( 'plugin_action_links_' . plugin_basename( __FILE__ ), 'srcp_action_links' );

function srcp_admin_menu() {
	add_options_page(
		__( 'ScamRead Checker', 'scamread-checker-promo' ),
		__( 'ScamRead Checker', 'scamread-checker-promo' ),
		'manage_options',
		'srcp',
		'srcp_settings_page'
	);
}

function srcp_action_links( $links ) {
	array_unshift( $links, '<a href="' . esc_url( admin_url( 'options-general.php?page=srcp' ) ) . '">' . esc_html__( 'Settings', 'scamread-checker-promo' ) . '</a>' );
	return $links;
}

function srcp_admin_init() {
	register_setting(
		'srcp',
		SRCP_OPTION,
		array(
			'type'              => 'array',
			'sanitize_callback' => 'srcp_sanitize',
			'default'           => srcp_defaults(),
		)
	);
}

function srcp_sanitize( $input ) {
	$input = is_array( $input ) ? $input : array();
	$url   = isset( $input['url'] ) ? esc_url_raw( trim( $input['url'] ) ) : '';
	return array(
		'enabled'   => empty( $input['enabled'] ) ? 0 : 1,
		'delay'     => isset( $input['delay'] ) ? min( 60, max( 0, (int) $input['delay'] ) ) : 6,
		'hide_days' => isset( $input['hide_days'] ) ? min( 90, max( 1, (int) $input['hide_days'] ) ) : 7,
		'url'       => $url ? $url : 'https://app.scamread.com/',
	);
}

function srcp_settings_page() {
	if ( ! current_user_can( 'manage_options' ) ) {
		return;
	}
	$s = srcp_settings();
	?>
	<div class="wrap">
		<h1><?php esc_html_e( 'ScamRead Checker pop-up', 'scamread-checker-promo' ); ?></h1>
		<p><?php esc_html_e( 'A small card in the bottom corner that invites visitors to try the free scam checker. It shows once per visit, and if a visitor closes it, it stays hidden for them for the number of days below.', 'scamread-checker-promo' ); ?></p>
		<form method="post" action="options.php">
			<?php settings_fields( 'srcp' ); ?>
			<table class="form-table" role="presentation">
				<tr>
					<th scope="row"><?php esc_html_e( 'Show the pop-up', 'scamread-checker-promo' ); ?></th>
					<td><label><input type="checkbox" name="<?php echo esc_attr( SRCP_OPTION ); ?>[enabled]" value="1" <?php checked( 1, (int) $s['enabled'] ); ?>> <?php esc_html_e( 'On', 'scamread-checker-promo' ); ?></label></td>
				</tr>
				<tr>
					<th scope="row"><label for="srcp-delay"><?php esc_html_e( 'Wait before showing (seconds)', 'scamread-checker-promo' ); ?></label></th>
					<td><input id="srcp-delay" type="number" min="0" max="60" name="<?php echo esc_attr( SRCP_OPTION ); ?>[delay]" value="<?php echo esc_attr( $s['delay'] ); ?>" class="small-text"></td>
				</tr>
				<tr>
					<th scope="row"><label for="srcp-days"><?php esc_html_e( 'After closing, hide for (days)', 'scamread-checker-promo' ); ?></label></th>
					<td><input id="srcp-days" type="number" min="1" max="90" name="<?php echo esc_attr( SRCP_OPTION ); ?>[hide_days]" value="<?php echo esc_attr( $s['hide_days'] ); ?>" class="small-text"></td>
				</tr>
				<tr>
					<th scope="row"><label for="srcp-url"><?php esc_html_e( 'Checker address', 'scamread-checker-promo' ); ?></label></th>
					<td><input id="srcp-url" type="url" name="<?php echo esc_attr( SRCP_OPTION ); ?>[url]" value="<?php echo esc_attr( $s['url'] ); ?>" class="regular-text"></td>
				</tr>
			</table>
			<?php submit_button(); ?>
		</form>
		<p class="description"><?php esc_html_e( 'If you use a page cache (LiteSpeed), purge it after changing these settings.', 'scamread-checker-promo' ); ?></p>
	</div>
	<?php
}

register_uninstall_hook( __FILE__, 'srcp_uninstall' );

function srcp_uninstall() {
	delete_option( SRCP_OPTION );
}
