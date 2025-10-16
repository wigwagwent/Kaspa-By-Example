use std::path::PathBuf;

/// Loads the .env file from the root of the git repo. 
/// This should be setup before any of the example code works.
pub fn load_users_env_file() {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let workspace_root = manifest_dir
        .parent()
        .expect("Folder: Rust") // Go up from your crate to workspace root
        .parent()
        .expect("Folder: Repo Root");

    println!("Workspace root: {}", workspace_root.display());
    let env_path = workspace_root.join(".env");

    dotenv::from_path(&env_path).ok();
}
