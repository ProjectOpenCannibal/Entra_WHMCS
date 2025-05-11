<?php
/**
 * Azure B2C SSO Login Module for WHMCS
 * Version: 1.0
 */

if (!defined('WHMCS')) {
    die('Access Denied');
}

use WHMCS\Database\Capsule;
use WHMCS\Auth;
use WHMCS\Config\Setting;

function azureb2c_config() {
    return [
        'name'        => 'Azure B2C SSO Login',
        'description' => 'Replace client login with Azure AD B2C authentication.',
        'version'     => '1.0',
        'author'      => 'YourName',
        'fields'      => [
            'TenantDomain' => [
                'FriendlyName' => 'Tenant Domain',
                'Type'         => 'text',
                'Size'         => '50',
                'Description'  => 'e.g. yourtenant.onmicrosoft.com',
            ],
            'PolicyName'   => [
                'FriendlyName' => 'B2C Policy',
                'Type'         => 'text',
                'Size'         => '30',
                'Description'  => 'e.g. B2C_1A_SignUpSignIn',
            ],
            'ClientID'     => [
                'FriendlyName' => 'Azure App Client ID',
                'Type'         => 'text',
                'Size'         => '40',
            ],
            'ClientSecret' => [
                'FriendlyName' => 'Client Secret',
                'Type'         => 'password',
                'Size'         => '60',
            ],
            'UsePKCE'      => [
                'FriendlyName' => 'Enable PKCE',
                'Type'         => 'yesno',
                'Description'  => 'Recommended for extra security.',
            ],
        ],
    ];
}

function azureb2c_activate() {
    // Create a custom client field to store Azure B2C object ID
    if (!Capsule::schema()->hasTable('tblcustomfields')) {
        return ['status' => 'error', 'description' => 'Custom fields table missing'];
    }
    // Check if field exists
    $exists = Capsule::table('tblcustomfields')
        ->where('fieldname', 'Azure B2C ID')
        ->where('type', 'client')
        ->exists();
    if (!$exists) {
        Capsule::table('tblcustomfields')->insert([
            'type'      => 'client',
            'fieldname' => 'Azure B2C ID',
            'fieldtype' => 'text',
            'adminonly' => 1,
            'required'  => 0,
        ]);
    }
    return ['status' => 'success', 'description' => 'AzureB2C module activated'];
}

function azureb2c_deactivate() {
    // Optionally remove custom field
    Capsule::table('tblcustomfields')
        ->where('fieldname', 'Azure B2C ID')
        ->where('type', 'client')
        ->delete();
    return ['status' => 'success', 'description' => 'AzureB2C module deactivated'];
}

function azureb2c_clientarea($vars) {
    // Handle OAuth callback
    if (!isset($_GET['code'])) {
        // No code = nothing to do
        return;
    }
    session_start();
    $code  = $_GET['code'];
    $state = $_GET['state'] ?? '';
    if (!$state || $state !== $_SESSION['azureb2c_state']) {
        die('Invalid state parameter');
    }
    unset($_SESSION['azureb2c_state']);

    // Load config
    $cfg          = AzureB2CConfig::get();
    $tenant       = $cfg['tenant'];
    $policy       = $cfg['policy'];
    $clientId     = $cfg['clientid'];
    $clientSecret = $cfg['secret'];
    $usePkce      = $cfg['pkce'];
    $redirectUri  = AzureB2CConfig::callbackUrl();

    // Exchange code for tokens
    $tokenUrl = "https://{$tenant}/{$tenant}/{$policy}/oauth2/v2.0/token";
    $postData = [
        'grant_type'    => 'authorization_code',
        'client_id'     => $clientId,
        'code'          => $code,
        'redirect_uri'  => $redirectUri,
        'scope'         => 'openid profile email',
    ];
    if ($usePkce) {
        $postData['code_verifier'] = $_SESSION['azureb2c_code_verifier'];
        unset($_SESSION['azureb2c_code_verifier']);
    } else {
        $postData['client_secret'] = $clientSecret;
    }

    $ch = curl_init($tokenUrl);
    curl_setopt($ch, CURLOPT_POST,        true);
    curl_setopt($ch, CURLOPT_POSTFIELDS,  http_build_query($postData));
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    $resp = curl_exec($ch);
    if (curl_errno($ch)) {
        die('Token request error: ' . curl_error($ch));
    }
    curl_close($ch);
    $tokenData = json_decode($resp, true);
    if (empty($tokenData['id_token'])) {
        die('Failed to get ID token');
    }
    $idToken = $tokenData['id_token'];

    // Decode payload (no signature verification here—add JWT lib for prod)
    $parts   = explode('.', $idToken);
    $payload = json_decode(base64_decode($parts[1]), true);
    $email   = $payload['email'] ?? ($payload['emails'][0] ?? null);
    $first   = $payload['given_name'] ?? '';
    $last    = $payload['family_name'] ?? '';
    $oid     = $payload['oid'] ?? $payload['sub'] ?? '';

    if (!$email) {
        die('Email claim not found');
    }

    // Find or create WHMCS client
    $client = Capsule::table('tblclients')->where('email', $email)->first();
    if ($client) {
        $clientId = $client->id;
        // Update name if changed
        $update = [];
        if ($first && $first !== $client->firstname) {
            $update['firstname'] = $first;
        }
        if ($last  && $last  !== $client->lastname) {
            $update['lastname'] = $last;
        }
        if ($update) {
            $update['clientid'] = $clientId;
            localAPI('UpdateClient', $update);
        }
    } else {
        // JIT create
        $pw = bin2hex(random_bytes(6));
        $data = [
            'firstname' => $first ?: 'Azure',
            'lastname'  => $last  ?: 'User',
            'email'     => $email,
            'password2' => $pw,
            'noemail'   => true,
        ];
        $res = localAPI('AddClient', $data);
        if ($res['result'] !== 'success') {
            die('WHMCS AddClient error: ' . $res['message']);
        }
        $clientId = $res['clientid'];
    }

    // Save Azure B2C ID into custom field
    Capsule::table('tblcustomfieldsvalues')
        ->updateOrInsert(
            ['fieldid' => Capsule::table('tblcustomfields')->where('fieldname','Azure B2C ID')->value('id'),
             'relid'   => $clientId],
            ['value'   => $oid]
        );

    // Log them in
    require_once __DIR__ . '/../../../init.php';
    $auth = new Auth();
    $auth->getInfobyID($clientId);
    $auth->setSessionVars();
    $auth->processLogin();

    header('Location: clientarea.php');
    exit;
}

// Helper for config and callback URL
class AzureB2CConfig {
    public static function get() {
        $settings = ModuleVars::getModuleParams('azureb2c'); // WHMCS helper
        return [
            'tenant'   => $settings['TenantDomain'],
            'policy'   => $settings['PolicyName'],
            'clientid' => $settings['ClientID'],
            'secret'   => $settings['ClientSecret'],
            'pkce'     => !empty($settings['UsePKCE']),
        ];
    }
    public static function callbackUrl() {
        $base = Setting::getValue('SystemURL');
        return $base . '/index.php?m=azureb2c';
    }
}
