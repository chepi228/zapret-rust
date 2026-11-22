pub fn answer(text: &str) -> Option<bool> {
    match text.trim().to_ascii_lowercase().as_str() {
        "y" | "yes" => Some(true),
        "" | "n" | "no" => Some(false),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn english_answers_are_exact_and_empty_input_declines() {
        for text in ["y", "Y", "yes", " YES "] {
            assert_eq!(answer(text), Some(true));
        }
        for text in ["n", "N", "no", " NO ", ""] {
            assert_eq!(answer(text), Some(false));
        }
        for text in ["yesterday", "д", "да", "б", "1", "2"] {
            assert_eq!(answer(text), None);
        }
    }
}
