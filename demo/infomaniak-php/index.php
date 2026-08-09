<?php
declare(strict_types=1);

const IK_ISSUER = 'https://login.infomaniak.com';
const IK_AUTHORIZE = IK_ISSUER . '/authorize';
const IK_TOKEN = IK_ISSUER . '/token';
const IK_USERINFO = IK_ISSUER . '/oauth2/userinfo';

$configPath = dirname(__DIR__, 2) . '/.n09-auth-config.php';
if (!is_file($configPath)) {
    http_response_code(503);
    exit('La passerelle N09 n’est pas encore configurée.');
}
$config = require $configPath;
$registryPath = dirname(__DIR__, 2) . '/.n09-admin.sqlite3';

session_name('n09_admin_auth');
session_set_cookie_params([
    'lifetime' => 0,
    'path' => '/',
    'secure' => true,
    'httponly' => true,
    'samesite' => 'Lax',
]);
session_start();

function b64url(string $bytes): string
{
    return rtrim(strtr(base64_encode($bytes), '+/', '-_'), '=');
}

function fail(string $message, int $status = 400): never
{
    http_response_code($status);
    page('Connexion non validée', '<p>' . htmlspecialchars($message) . '</p><p>Aucun compte et aucun droit n’ont été modifiés.</p>', false);
    exit;
}

function postForm(string $url, array $fields): array
{
    $handle = curl_init($url);
    curl_setopt_array($handle, [
        CURLOPT_POST => true,
        CURLOPT_POSTFIELDS => http_build_query($fields),
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_HTTPHEADER => ['Accept: application/json', 'Content-Type: application/x-www-form-urlencoded'],
        CURLOPT_TIMEOUT => 15,
    ]);
    $body = curl_exec($handle);
    $status = curl_getinfo($handle, CURLINFO_RESPONSE_CODE);
    if (!is_string($body)) fail('Infomaniak est momentanément inaccessible.', 502);
    $json = json_decode($body, true);
    if ($status < 200 || $status >= 300 || !is_array($json)) {
        $detail = is_array($json) ? ($json['error_description'] ?? $json['error'] ?? 'réponse invalide') : 'réponse invalide';
        fail('Infomaniak refuse l’échange final : ' . $detail, 502);
    }
    return $json;
}

function getJson(string $url, string $accessToken): array
{
    $handle = curl_init($url);
    curl_setopt_array($handle, [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_HTTPHEADER => ['Accept: application/json', 'Authorization: Bearer ' . $accessToken],
        CURLOPT_TIMEOUT => 15,
    ]);
    $body = curl_exec($handle);
    $status = curl_getinfo($handle, CURLINFO_RESPONSE_CODE);
    $json = is_string($body) ? json_decode($body, true) : null;
    if ($status !== 200 || !is_array($json)) fail('Le profil signé par Infomaniak n’est pas disponible.', 502);
    return $json;
}

function resolveNskIdentity(string $registryPath, string $issuer, string $subject): ?array
{
    if (!class_exists('SQLite3') || !is_file($registryPath)) {
        fail('Le registre central NSK n’est pas disponible.', 503);
    }
    try {
        $database = new SQLite3($registryPath, SQLITE3_OPEN_READONLY);
        $database->busyTimeout(2000);
        $statement = $database->prepare(
            'SELECT i.identity_id, i.display_name, i.email, i.status '
            . 'FROM external_identities e JOIN identities i ON i.identity_id = e.identity_id '
            . 'WHERE e.issuer = :issuer AND e.subject = :subject '
            . "AND e.status = 'active' LIMIT 1"
        );
        $statement->bindValue(':issuer', $issuer, SQLITE3_TEXT);
        $statement->bindValue(':subject', $subject, SQLITE3_TEXT);
        $result = $statement->execute();
        $identity = $result->fetchArray(SQLITE3_ASSOC);
        $database->close();
        return is_array($identity) ? $identity : null;
    } catch (Throwable) {
        fail('Le registre central NSK ne peut pas être consulté.', 503);
    }
}

function page(string $title, string $content, bool $success = true): void
{
    $safeTitle = htmlspecialchars($title);
    $mark = $success ? '✓' : '!';
    $markBackground = $success ? '#dff4e9' : '#fff0d8';
    $markColor = $success ? '#176341' : '#8a4f12';
    echo <<<HTML
<!doctype html><html lang="fr"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>{$safeTitle} · N09 Administration</title><style>
*{box-sizing:border-box}body{margin:0;background:#f3f6f4;color:#18221e;font:16px Arial,sans-serif;display:grid;place-items:center;min-height:100vh}.card{width:min(620px,calc(100% - 36px));background:#fff;border:1px solid #dfe6e2;border-radius:18px;padding:34px;box-shadow:0 12px 40px #19392d14}.brand{color:#21825e;font-size:12px;font-weight:800;letter-spacing:1px}.mark{width:52px;height:52px;margin-top:24px;border-radius:15px;display:grid;place-items:center;background:{$markBackground};color:{$markColor};font-size:24px;font-weight:bold}h1{font:600 31px Georgia,serif;margin:22px 0 12px}p{color:#5d6c65;line-height:1.6}.facts{padding:16px;border-radius:10px;background:#f3f7f5;margin:20px 0}.facts strong{color:#173e32}a.button{display:inline-block;padding:12px 17px;border-radius:9px;background:#173e32;color:#fff;text-decoration:none;font-weight:bold}.note{font-size:13px}
</style></head><body><main class="card"><div class="brand">N09 · ADMINISTRATION · NSK TECH 09</div><div class="mark">{$mark}</div><h1>{$safeTitle}</h1>{$content}</main></body></html>
HTML;
}

$path = rtrim((string) parse_url($_SERVER['REQUEST_URI'] ?? '/', PHP_URL_PATH), '/') ?: '/';

if ($path === '/auth/infomaniak/start' && !isset($_GET['code'])) {
    $state = b64url(random_bytes(32));
    $nonce = b64url(random_bytes(32));
    $verifier = b64url(random_bytes(48));
    $_SESSION['oidc'] = ['state' => $state, 'nonce' => $nonce, 'verifier' => $verifier, 'expires' => time() + 600];
    $query = http_build_query([
        'client_id' => $config['client_id'],
        'redirect_uri' => $config['redirect_uri'],
        'response_type' => 'code',
        'scope' => 'openid profile email',
        'state' => $state,
        'nonce' => $nonce,
        'code_challenge' => b64url(hash('sha256', $verifier, true)),
        'code_challenge_method' => 'S256',
    ]);
    header('Cache-Control: no-store');
    header('Location: ' . IK_AUTHORIZE . '?' . $query, true, 302);
    exit;
}

if ($path === '/auth/infomaniak/callback' || ($path === '/auth/infomaniak/start' && isset($_GET['code']))) {
    $transaction = $_SESSION['oidc'] ?? null;
    unset($_SESSION['oidc']);
    if (!is_array($transaction) || ($transaction['expires'] ?? 0) < time()) fail('La tentative de connexion a expiré.');
    if (!isset($_GET['state'], $_GET['code']) || !hash_equals($transaction['state'], (string) $_GET['state'])) fail('La preuve anti-falsification ne correspond pas.');
    $tokens = postForm(IK_TOKEN, [
        'grant_type' => 'authorization_code',
        'code' => (string) $_GET['code'],
        'redirect_uri' => $config['redirect_uri'],
        'client_id' => $config['client_id'],
        'client_secret' => $config['client_secret'],
        'code_verifier' => $transaction['verifier'],
    ]);
    if (empty($tokens['access_token'])) fail('Infomaniak n’a fourni aucune preuve d’accès.', 502);
    $identity = getJson(IK_USERINFO, $tokens['access_token']);
    if (empty($identity['sub'])) fail('Infomaniak n’a fourni aucun identifiant stable.', 502);
    $nskIdentity = resolveNskIdentity($registryPath, IK_ISSUER, (string) $identity['sub']);
    $name = htmlspecialchars($identity['name'] ?? trim(($identity['given_name'] ?? '') . ' ' . ($identity['family_name'] ?? '')) ?: 'Utilisateur Infomaniak');
    $subject = htmlspecialchars((string) $identity['sub']);
    $email = isset($identity['email']) ? '<p>E-mail transmis : <strong>' . htmlspecialchars((string) $identity['email']) . '</strong></p>' : '<p>Aucune adresse e-mail n’a été nécessaire.</p>';
    session_regenerate_id(true);
    if ($nskIdentity === null) {
        page('Rattachement NSK requis', "<p>Infomaniak a authentifié <strong>{$name}</strong>, mais cette preuve externe n’est rattachée à aucune identité NSK.</p><div class=\"facts\"><p>Identifiant externe stable : <strong>{$subject}</strong></p>{$email}<p>Aucun compte, rôle ou droit n’a été créé automatiquement.</p></div><a class=\"button\" href=\"/\">Retour à N09 – Administration</a>", false);
        exit;
    }
    $nskId = htmlspecialchars((string) $nskIdentity['identity_id']);
    $nskName = htmlspecialchars((string) $nskIdentity['display_name']);
    $nskStatus = htmlspecialchars((string) $nskIdentity['status']);
    page('Identité NSK reconnue', "<p>Bienvenue <strong>{$nskName}</strong>. La passerelle d’évaluation Infomaniak a retrouvé ton identité centrale dans le registre NSK.</p><div class=\"facts\"><p>Identifiant NSK immuable : <strong>{$nskId}</strong></p><p>Statut de l’identité : <strong>{$nskStatus}</strong></p><p>Identifiant Infomaniak : <strong>{$subject}</strong></p><p>Aucune session NSK et aucun droit applicatif n’ont été créés.</p></div><p class=\"note\">Banc de validation isolé : il ne devient un service d’authentification qu’après validation cryptographique complète du jeton conformément au contrat OIDC.</p><a class=\"button\" href=\"/\">Retour à N09 – Administration</a>");
    exit;
}

page('Première connexion réelle', '<p>Cette passerelle isolée vérifie le fonctionnement d’Infomaniak Auth avant son raccordement définitif au registre central des identités.</p><div class="facts"><p><strong>Lecture seule :</strong> profil et adresse e-mail autorisés.</p><p><strong>Zéro privilège implicite :</strong> une identité externe inconnue n’obtient aucun droit.</p></div><a class="button" href="/auth/infomaniak/start">Continuer avec Infomaniak</a><p class="note">Démonstrateur technique · aucun mot de passe NSK supplémentaire.</p>');
