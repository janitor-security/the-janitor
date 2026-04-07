//! Authoritative file-surface classification for routing and policy.

use std::path::Path;

/// Stable semantic surface kind resolved from filename or extension.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SurfaceKind {
    Unknown,
    Python,
    Rust,
    Cpp,
    Java,
    CSharp,
    Go,
    JavaScript,
    Jsx,
    TypeScript,
    Tsx,
    Glsl,
    Scala,
    Bash,
    Cmd,
    Zsh,
    ObjectiveC,
    ObjectiveCpp,
    Ruby,
    Php,
    Swift,
    Lua,
    Nix,
    Gdscript,
    Terraform,
    Hcl,
    Json,
    Toml,
    Yaml,
    Xml,
    Proto,
    Dockerfile,
    Cmake,
    Starlark,
    GoMod,
    GoVersion,
    Properties,
    Env,
    Bat,
    PowerShell,
    Patch,
    PermittedImages,
    Csv,
    Markdown,
    Rst,
    Lock,
    Svg,
    Map,
}

impl SurfaceKind {
    /// Classify a path using canonical filenames first, then extension.
    pub fn from_path(path: &Path) -> Self {
        let file_name = path.file_name().and_then(|s| s.to_str()).unwrap_or("");
        match file_name {
            "Dockerfile" => return Self::Dockerfile,
            "CMakeLists.txt" => return Self::Cmake,
            "BUILD" | "WORKSPACE" | "MODULE.bazel" => return Self::Starlark,
            _ => {}
        }
        if file_name.starts_with("BUILD.") {
            return Self::Starlark;
        }
        match path.extension().and_then(|s| s.to_str()).unwrap_or("") {
            "py" => Self::Python,
            "rs" => Self::Rust,
            "cpp" | "cxx" | "cc" | "h" | "hpp" | "c" => Self::Cpp,
            "java" => Self::Java,
            "cs" => Self::CSharp,
            "go" => Self::Go,
            "js" | "mjs" | "cjs" => Self::JavaScript,
            "jsx" => Self::Jsx,
            "ts" => Self::TypeScript,
            "tsx" => Self::Tsx,
            "glsl" | "vert" | "frag" => Self::Glsl,
            "scala" => Self::Scala,
            "sh" | "bash" => Self::Bash,
            "cmd" => Self::Cmd,
            "zsh" => Self::Zsh,
            "m" => Self::ObjectiveC,
            "mm" => Self::ObjectiveCpp,
            "rb" => Self::Ruby,
            "php" => Self::Php,
            "swift" => Self::Swift,
            "lua" => Self::Lua,
            "nix" => Self::Nix,
            "gd" => Self::Gdscript,
            "tf" => Self::Terraform,
            "hcl" => Self::Hcl,
            "json" => Self::Json,
            "toml" => Self::Toml,
            "yaml" | "yml" => Self::Yaml,
            "xml" => Self::Xml,
            "proto" => Self::Proto,
            "bzl" => Self::Starlark,
            "mod" => Self::GoMod,
            "go-version" => Self::GoVersion,
            "properties" => Self::Properties,
            "env" => Self::Env,
            "bat" => Self::Bat,
            "ps1" => Self::PowerShell,
            "patch" => Self::Patch,
            "permitted-images" => Self::PermittedImages,
            "csv" => Self::Csv,
            "md" => Self::Markdown,
            "rst" => Self::Rst,
            "lock" => Self::Lock,
            "svg" => Self::Svg,
            "map" => Self::Map,
            _ => Self::Unknown,
        }
    }

    /// Canonical language/router label consumed by Forge.
    pub fn language_key(self) -> &'static str {
        match self {
            Self::Unknown => "",
            Self::Python => "py",
            Self::Rust => "rs",
            Self::Cpp => "cpp",
            Self::Java => "java",
            Self::CSharp => "cs",
            Self::Go => "go",
            Self::JavaScript => "js",
            Self::Jsx => "jsx",
            Self::TypeScript => "ts",
            Self::Tsx => "tsx",
            Self::Glsl => "glsl",
            Self::Scala => "scala",
            Self::Bash => "sh",
            Self::Cmd => "cmd",
            Self::Zsh => "zsh",
            Self::ObjectiveC => "m",
            Self::ObjectiveCpp => "mm",
            Self::Ruby => "rb",
            Self::Php => "php",
            Self::Swift => "swift",
            Self::Lua => "lua",
            Self::Nix => "nix",
            Self::Gdscript => "gd",
            Self::Terraform => "tf",
            Self::Hcl => "hcl",
            Self::Json => "json",
            Self::Toml => "toml",
            Self::Yaml => "yaml",
            Self::Xml => "xml",
            Self::Proto => "proto",
            Self::Dockerfile => "dockerfile",
            Self::Cmake => "cmake",
            Self::Starlark => "bzl",
            Self::GoMod => "mod",
            Self::GoVersion => "go-version",
            Self::Properties => "properties",
            Self::Env => "env",
            Self::Bat => "bat",
            Self::PowerShell => "ps1",
            Self::Patch => "patch",
            Self::PermittedImages => "permitted-images",
            Self::Csv => "csv",
            Self::Markdown => "md",
            Self::Rst => "rst",
            Self::Lock => "lock",
            Self::Svg => "svg",
            Self::Map => "map",
        }
    }

    /// Text surfaces that are authoritative configuration or source even when
    /// they do not have a grammar-backed hot path in `lang_for_ext`.
    pub fn is_definitive_text(self) -> bool {
        matches!(
            self,
            Self::Nix
                | Self::Json
                | Self::Toml
                | Self::Yaml
                | Self::Xml
                | Self::TypeScript
                | Self::Tsx
                | Self::Terraform
                | Self::Hcl
                | Self::Gdscript
                | Self::GoMod
                | Self::GoVersion
                | Self::Properties
                | Self::Env
                | Self::Bat
                | Self::PowerShell
                | Self::Patch
                | Self::PermittedImages
                | Self::Csv
                | Self::Markdown
                | Self::Rst
                | Self::Lock
                | Self::Svg
                | Self::Map
                | Self::Dockerfile
                | Self::Cmake
                | Self::Starlark
                | Self::Proto
        )
    }

    /// Stable label for metadata/reporting flows expecting extension-like tags.
    pub fn telemetry_label(self) -> String {
        self.language_key().to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::SurfaceKind;
    use std::path::Path;

    #[test]
    fn classifies_canonical_filenames() {
        assert_eq!(
            SurfaceKind::from_path(Path::new("Dockerfile")),
            SurfaceKind::Dockerfile
        );
        assert_eq!(
            SurfaceKind::from_path(Path::new("CMakeLists.txt")),
            SurfaceKind::Cmake
        );
        assert_eq!(
            SurfaceKind::from_path(Path::new("WORKSPACE")),
            SurfaceKind::Starlark
        );
        assert_eq!(
            SurfaceKind::from_path(Path::new("pkg/BUILD.bazel")),
            SurfaceKind::Starlark
        );
    }

    #[test]
    fn classifies_regular_extensions() {
        assert_eq!(
            SurfaceKind::from_path(Path::new("src/main.rs")),
            SurfaceKind::Rust
        );
        assert_eq!(
            SurfaceKind::from_path(Path::new("src/app.py")),
            SurfaceKind::Python
        );
        assert_eq!(
            SurfaceKind::from_path(Path::new("src/app.ts")),
            SurfaceKind::TypeScript
        );
    }
}
