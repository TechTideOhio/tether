use crate::error::TetherError;
use regex::Regex;

pub struct RedactionEngine {
    patterns: Vec<(Regex, &'static str)>,
    verify_patterns: Vec<Regex>,
}

impl Default for RedactionEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl RedactionEngine {
    pub fn new() -> Self {
        let patterns = vec![
            // Anthropic keys
            (
                Regex::new(r"sk-ant-[a-zA-Z0-9_\-]{20,}").expect("valid regex"),
                "[REDACTED_ANTHROPIC_KEY]",
            ),
            // OpenAI keys
            (
                Regex::new(r"sk-[a-zA-Z0-9_\-]{20,}").expect("valid regex"),
                "[REDACTED_OPENAI_KEY]",
            ),
            // GitHub tokens
            (
                Regex::new(r"gh[pousr]_[a-zA-Z0-9]{30,}").expect("valid regex"),
                "[REDACTED_GITHUB_TOKEN]",
            ),
            // AWS Access Keys
            (
                Regex::new(r"AKIA[0-9A-Z]{16}").expect("valid regex"),
                "[REDACTED_AWS_ACCESS_KEY]",
            ),
            // Bearer Authorization tokens
            (
                Regex::new(r"(?i)Bearer\s+[a-zA-Z0-9_\-\.]{20,}").expect("valid regex"),
                "Bearer [REDACTED_BEARER_TOKEN]",
            ),
            // Email addresses
            (
                Regex::new(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}")
                    .expect("valid regex"),
                "[REDACTED_EMAIL]",
            ),
            // Windows user paths: C:\Users\Username
            (
                Regex::new(r"(?i)[a-z]:\\Users\\[a-zA-Z0-9_\.\-]+").expect("valid regex"),
                r"C:\Users\[REDACTED_USER]",
            ),
            // Unix user paths: /Users/Username or /home/Username
            (
                Regex::new(r"/(?:Users|home)/[a-zA-Z0-9_\.\-]+").expect("valid regex"),
                "/Users/[REDACTED_USER]",
            ),
        ];

        let verify_patterns = vec![
            Regex::new(r"gh[pousr]_[a-zA-Z0-9]{30,}").expect("valid regex"),
            Regex::new(r"sk-ant-[a-zA-Z0-9_\-]{20,}").expect("valid regex"),
            Regex::new(r"AKIA[0-9A-Z]{16}").expect("valid regex"),
        ];

        Self {
            patterns,
            verify_patterns,
        }
    }

    pub fn redact(&self, text: &str) -> Result<String, TetherError> {
        let mut result = text.to_string();
        for (re, replacement) in &self.patterns {
            result = re.replace_all(&result, *replacement).to_string();
        }

        for verify in &self.verify_patterns {
            if let Some(mat) = verify.find(&result) {
                return Err(TetherError::RedactionFailure(format!(
                    "Residual secret pattern matched: {}",
                    mat.as_str()
                )));
            }
        }

        Ok(result)
    }
}

pub fn scrub_text(input: &str) -> Result<String, TetherError> {
    let engine = RedactionEngine::new();
    engine.redact(input)
}
