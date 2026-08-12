//! Prépare le terrain pour l'embarquement du bundle web.
//!
//! `rust-embed` lit `web/dist` au moment de l'expansion de la macro et échoue
//! si le dossier n'existe pas — ce qui serait le cas sur un dépôt fraîchement
//! cloné, avant tout build du front. Le dossier est donc créé ici, et cargo est
//! prié de recompiler dès que son contenu change, sans quoi un `npm run build`
//! suivi d'un `cargo build` conserverait l'ancien bundle embarqué.

use std::path::Path;

fn main() {
    let dist = Path::new("web/dist");
    println!("cargo:rerun-if-changed=web/dist");
    println!("cargo:rerun-if-changed=build.rs");

    if !dist.exists() {
        std::fs::create_dir_all(dist)
            .unwrap_or_else(|err| panic!("création de {} impossible : {err}", dist.display()));
    }
}
