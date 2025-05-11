<?php
/**
 * Hooks for Azure B2C SSO Module
 */
if (!defined('WHMCS')) {
    die('Access Denied');
}

use WHMCS\Session;
use WHMCS\Auth;

// Redirect login page to Azure B2C
add_hook('ClientAreaPageLogin', 1, function($vars) {
    if (isset($_GET['code'])) {
        return; // let callback handler do its thing
    }
    session_start();
    $cfg = AzureB2CConfig::get();
    $tenant  = $cfg['tenant'];
    $policy  = $cfg['policy'];
    $client  = $cfg['clientid'];
    $redir   = AzureB2CConfig::callbackUrl();

    // state & PKCE
    $state = bin2hex(random_bytes(16));
    $_SESSION['azureb2c_state'] = $state;
    $url = "https://{$tenant}/{$tenant}/{$policy}/oauth2/v2.0/authorize"
         . "?response_type=code&response_mode=query"
         . "&client_id=" . urlencode($client)
         . "&redirect_uri=" . urlencode($redir)
         . "&scope=" . urlencode('openid profile email')
         . "&state=" . urlencode($state);
    if ($cfg['pkce']) {
        $verifier = bin2hex(random_bytes(32));
        $_SESSION['azureb2c_code_verifier'] = $verifier;
        $challenge = rtrim(strtr(base64_encode(hash('sha256', $verifier, true)), '+/', '-_'), '=');
        $url .= "&code_challenge={$challenge}&code_challenge_method=S256";
    }
    header("Location: {$url}");
    exit;
});

// Optional: remove local register page
add_hook('ClientAreaPageRegister', 1, function($vars) {
    header('Location: clientarea.php');
    exit;
});

// Optional: remove sidebar login widget
add_hook('ClientAreaPrimarySidebar', 1, function($sidebar) {
    if ($sidebar->getChild('Client Login')) {
        $sidebar->removeChild('Client Login');
    }
});

// Optional: sync logout with Azure B2C sign-out
add_hook('ClientAreaPageLogout', 1, function($vars) {
    // Perform WHMCS logout
    $auth = new Auth();
    $auth->logout();

    // Redirect to Azure B2C logout to clear its session (tweak policy if needed)
    $cfg = AzureB2CConfig::get();
    $tenant = $cfg['tenant'];
    $policy = $cfg['policy'];
    $postLogout = AzureB2CConfig::callbackUrl(); // or homepage
    $logoutUrl = "https://{$tenant}/{$tenant}/{$policy}/oauth2/v2.0/logout"
               . "?post_logout_redirect_uri=" . urlencode($postLogout);
    header("Location: {$logoutUrl}");
    exit;
});
