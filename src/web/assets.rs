//! Service du bundle Vue compilé, servi directement depuis le binaire.

use axum::http::{header, StatusCode, Uri};
use axum::response::{IntoResponse, Response};
use rust_embed::RustEmbed;

#[derive(RustEmbed)]
#[folder = "web/dist"]
struct Assets;

/// Affiché lorsque le binaire a été compilé sans avoir construit le front.
const MISSING_UI: &str = r#"<!doctype html>
<meta charset="utf-8">
<title>tiv-gateway</title>
<style>body{font-family:system-ui,sans-serif;max-width:40rem;margin:4rem auto;padding:0 1rem;line-height:1.6}code{background:#eee;padding:.15rem .35rem;border-radius:.25rem}</style>
<h1>L'interface web n'a pas été empaquetée</h1>
<p>L'API fonctionne, mais aucun build du front n'est embarqué dans ce binaire.</p>
<p>Construisez-le avec <code>npm --prefix web ci &amp;&amp; npm --prefix web run build</code>, puis recompilez le binaire Rust.</p>
"#;

/// Sert un fichier statique, avec repli sur `index.html` pour laisser la SPA
/// gérer son propre routage.
pub async fn serve(uri: Uri) -> Response {
    let path = uri.path().trim_start_matches('/');
    let path = if path.is_empty() { "index.html" } else { path };

    if let Some(response) = file(path) {
        return response;
    }
    // Un lien profond comme /routing doit atteindre la SPA, mais un asset
    // manquant doit rester un 404 plutôt que de renvoyer discrètement du HTML.
    if !path.contains('.') {
        if let Some(response) = file("index.html") {
            return response;
        }
    }
    if path == "index.html" {
        return (
            StatusCode::OK,
            [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
            MISSING_UI,
        )
            .into_response();
    }
    (StatusCode::NOT_FOUND, "introuvable").into_response()
}

fn file(path: &str) -> Option<Response> {
    let asset = Assets::get(path)?;
    let mime = asset.metadata.mimetype();
    // Vite empreinte tout ce qui se trouve sous /assets : ces fichiers peuvent
    // donc être mis en cache agressivement.
    let cache_control = if path.starts_with("assets/") {
        "public, max-age=31536000, immutable"
    } else {
        "no-cache"
    };
    Some(
        (
            StatusCode::OK,
            [
                (header::CONTENT_TYPE, mime),
                (header::CACHE_CONTROL, cache_control),
            ],
            asset.data.into_owned(),
        )
            .into_response(),
    )
}
