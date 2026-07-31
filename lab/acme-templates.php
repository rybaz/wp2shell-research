<?php
/**
 * Plugin Name: ACME Template Store  (LAB INSTRUMENT — DELIBERATELY VULNERABLE)
 * Description: Models a common real-world plugin anti-pattern for wp2shell research:
 *   a PUBLIC REST write route that trusts the args-schema sanitizer for both the
 *   filename and the body, and writes the attacker-supplied name verbatim (guarded
 *   only by basename() against traversal). On a DIRECT call, core runs the schema
 *   sanitizers (wp_kses_post strips PHP). Reached through the CVE-2026-63030 desync,
 *   sanitize_params is skipped, so a raw <?php ... ?> body lands in an attacker-named
 *   .php that the server then executes.
 *
 *   Install ONLY on an isolated test instance (wp-content/mu-plugins/). Never deploy
 *   on a real site. Authorized security research only.
 */
add_action('rest_api_init', function () {
    register_rest_route('acme/v1', '/save-file', array(
        'methods'             => 'POST',
        'permission_callback' => '__return_true',
        'args' => array(
            'name'    => array('required' => true, 'sanitize_callback' => 'sanitize_file_name'),
            'content' => array('required' => true, 'sanitize_callback' => 'wp_kses_post'),
        ),
        'callback' => function (WP_REST_Request $req) {
            $dir = WP_CONTENT_DIR . '/uploads/acme-templates';
            if (!is_dir($dir)) { wp_mkdir_p($dir); }
            $name    = (string) $req->get_param('name');     // trusts schema sanitizer; keeps extension
            $content = (string) $req->get_param('content');
            $path    = $dir . '/' . basename($name);         // basename() blocks traversal ONLY
            file_put_contents($path, $content);
            return array('stored_file' => str_replace(ABSPATH, '', $path), 'bytes' => strlen($content));
        },
    ));
});
