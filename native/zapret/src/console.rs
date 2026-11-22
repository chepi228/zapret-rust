//! Console presentation shared by the interactive menus and the safe preview.
#[path = "console/image.rs"]
mod image;
use std::io::{self, IsTerminal, Write};
use windows_sys::Win32::{
    Foundation::HANDLE,
    System::Console::{
        CONSOLE_SCREEN_BUFFER_INFO, COORD, ENABLE_VIRTUAL_TERMINAL_PROCESSING,
        FillConsoleOutputAttribute, FillConsoleOutputCharacterW, GetConsoleMode,
        GetConsoleScreenBufferInfo, GetStdHandle, STD_OUTPUT_HANDLE, SetConsoleCursorPosition,
        SetConsoleMode, SetConsoleTextAttribute,
    },
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Tone {
    Border,
    Accent,
    Secondary,
    Text,
    Primary,
    Good,
    Warning,
    Bad,
}

impl Tone {
    fn ansi(self) -> &'static str {
        match self {
            Self::Border => "\x1b[38;2;105;105;115m",
            Self::Accent => "\x1b[38;2;255;209;232m",
            Self::Secondary => "\x1b[38;2;223;192;255m",
            Self::Text => "\x1b[38;2;192;192;192m",
            Self::Primary => "\x1b[38;2;245;245;245m",
            Self::Good => "\x1b[38;2;80;220;100m",
            Self::Warning => "\x1b[38;2;245;210;120m",
            Self::Bad => "\x1b[38;2;245;105;105m",
        }
    }
    fn classic(self) -> u16 {
        match self {
            Self::Border => 8,
            Self::Accent | Self::Primary => 15,
            Self::Secondary => 13,
            Self::Text => 7,
            Self::Good => 10,
            Self::Warning => 14,
            Self::Bad => 12,
        }
    }
}

#[derive(Clone, Copy)]
pub struct Viewport {
    pub columns: usize,
    pub rows: usize,
}

impl Viewport {
    pub fn current() -> Self {
        let mut info = CONSOLE_SCREEN_BUFFER_INFO::default();
        // SAFETY: the standard output handle is borrowed; info is writable.
        if unsafe { GetConsoleScreenBufferInfo(GetStdHandle(STD_OUTPUT_HANDLE), &mut info) } != 0 {
            Self {
                columns: (info.srWindow.Right - info.srWindow.Left + 1).max(1) as usize,
                rows: (info.srWindow.Bottom - info.srWindow.Top + 1).max(1) as usize,
            }
        } else {
            Self {
                columns: 80,
                rows: 30,
            }
        }
    }
    pub fn inner_width(self) -> usize {
        self.columns.saturating_sub(4).clamp(1, 74)
    }
}

#[derive(Clone)]
struct Span {
    text: String,
    tone: Tone,
}

type Line = Vec<Span>;

pub struct Frame {
    width: usize,
    lines: Vec<Line>,
}

impl Frame {
    pub fn new(viewport: Viewport, title: &str) -> Self {
        let mut frame = Self {
            width: viewport.inner_width(),
            lines: Vec::new(),
        };
        frame.border('╭', '╮', title);
        frame
    }
    fn border(&mut self, left: char, right: char, title: &str) {
        let title = if title.is_empty() {
            String::new()
        } else {
            format!(" {title} ")
        };
        let title = ellipsis(&title, self.width);
        let padding = self.width - title.chars().count();
        let left_padding = padding / 2;
        self.lines.push(vec![
            Span {
                text: format!("{left}{}", "─".repeat(left_padding)),
                tone: Tone::Border,
            },
            Span {
                text: title,
                tone: Tone::Accent,
            },
            Span {
                text: format!("{}{right}", "─".repeat(padding - left_padding)),
                tone: Tone::Border,
            },
        ]);
    }
    pub fn separator(&mut self, title: &str) {
        self.border('├', '┤', title);
    }
    pub fn row(&mut self, text: &str, tone: Tone) {
        for text in wrap(text, self.width) {
            let padding = self.width - text.chars().count();
            self.lines.push(vec![
                Span {
                    text: "│".into(),
                    tone: Tone::Border,
                },
                Span {
                    text: text + &" ".repeat(padding),
                    tone,
                },
                Span {
                    text: "│".into(),
                    tone: Tone::Border,
                },
            ]);
        }
    }
    pub fn item(&mut self, key: impl std::fmt::Display, text: &str, tone: Tone) {
        self.row(&format!(" {key:>2}  {text}"), tone);
    }
    pub fn height(&self) -> usize {
        self.lines.len() + 1 // Includes the bottom border.
    }
    fn complete(mut self) -> Vec<Line> {
        self.border('╰', '╯', "");
        self.lines
    }
    pub fn show(self) -> io::Result<()> {
        self.draw(true)
    }
    pub fn append(self) -> io::Result<()> {
        self.draw(false)
    }
    fn draw(self, clear: bool) -> io::Result<()> {
        let terminal = Terminal::new();
        let mut output = io::stdout().lock();
        if clear {
            terminal.clear(&mut output)?;
        } else {
            terminal.clear_line(&mut output)?;
        }
        for line in self.complete() {
            for span in line {
                terminal.write(&mut output, &span.text, span.tone)?;
            }
            writeln!(output)?;
        }
        terminal.reset(&mut output)?;
        output.flush()
    }
    #[cfg(test)]
    pub(crate) fn has_tone(&self, tone: Tone, text: &str) -> bool {
        self.lines
            .iter()
            .flatten()
            .any(|span| span.tone == tone && span.text.contains(text))
    }
    pub fn plain(self) -> String {
        self.complete()
            .into_iter()
            .map(|line| line.into_iter().map(|span| span.text).collect::<String>() + "\n")
            .collect()
    }
}

pub fn line(text: &str, tone: Tone) -> io::Result<()> {
    let terminal = Terminal::new();
    let mut output = io::stdout().lock();
    terminal.clear_line(&mut output)?;
    terminal.write(&mut output, text, tone)?;
    terminal.reset(&mut output)?;
    writeln!(output)?;
    output.flush()
}

pub fn status(text: &str, tone: Tone) -> io::Result<()> {
    let terminal = Terminal::new();
    if !terminal.interactive {
        return Ok(());
    }
    let mut output = io::stdout().lock();
    terminal.clear_line(&mut output)?;
    terminal.write(
        &mut output,
        &ellipsis(text, Viewport::current().columns.saturating_sub(1).max(1)),
        tone,
    )?;
    terminal.reset(&mut output)?;
    output.flush()
}

// Menu strings use single-cell Cyrillic, Latin and box-drawing characters, as in
// the original console. Count characters rather than UTF-8 bytes when padding.
fn ellipsis(text: &str, width: usize) -> String {
    if text.chars().count() <= width {
        return text.to_owned();
    }
    text.chars()
        .take(width.saturating_sub(1))
        .chain(['…'])
        .collect()
}

fn wrap(text: &str, width: usize) -> Vec<String> {
    let width = width.max(1);
    let indent = text
        .chars()
        .take_while(|c| c.is_whitespace())
        .count()
        .min(width.saturating_sub(2));
    let continuation = (indent + 2).min(width - 1);
    let mut lines = Vec::new();
    // Keep intentional spaces between menu numbers and labels. Reflow only at
    // the line boundary, splitting a long unbroken token without dropping it.
    let characters: Vec<_> = text
        .trim()
        .chars()
        .map(|character| {
            if character.is_whitespace() {
                ' '
            } else if character.is_control() {
                '�'
            } else {
                character
            }
        })
        .collect();
    let mut rest = characters.as_slice();
    let mut padding = indent;
    loop {
        let available = width - padding;
        if rest.len() <= available {
            lines.push(" ".repeat(padding) + &rest.iter().collect::<String>());
            break;
        }
        let split = rest[..=available]
            .iter()
            .rposition(|c| *c == ' ')
            .filter(|position| *position > 0)
            .unwrap_or(available);
        lines.push(" ".repeat(padding) + &rest[..split].iter().collect::<String>());
        rest = &rest[split..];
        while rest.first() == Some(&' ') {
            rest = &rest[1..];
        }
        padding = continuation;
    }
    lines
}

pub fn prompt(label: &str) -> io::Result<()> {
    let terminal = Terminal::new();
    let mut output = io::stdout().lock();
    terminal.write(&mut output, &format!("{label}: "), Tone::Accent)?;
    terminal.reset(&mut output)?;
    output.flush()
}

struct Terminal {
    handle: HANDLE,
    mode: Option<u32>,
    attributes: Option<u16>,
    ansi: bool,
    color: bool,
    interactive: bool,
}

impl Terminal {
    fn clear_line(&self, output: &mut impl Write) -> io::Result<()> {
        if self.interactive {
            if self.ansi {
                write!(output, "\r\x1b[2K")?;
            } else {
                write!(
                    output,
                    "\r{}\r",
                    " ".repeat(Viewport::current().columns.saturating_sub(1))
                )?;
            }
        }
        Ok(())
    }
    fn new() -> Self {
        let interactive = io::stdout().is_terminal();
        let handle = unsafe { GetStdHandle(STD_OUTPUT_HANDLE) };
        let mut mode = 0;
        let mode =
            (interactive && unsafe { GetConsoleMode(handle, &mut mode) } != 0).then_some(mode);
        let mut info = CONSOLE_SCREEN_BUFFER_INFO::default();
        let attributes = (interactive
            && unsafe { GetConsoleScreenBufferInfo(handle, &mut info) } != 0)
            .then_some(info.wAttributes);
        let ansi = mode.is_some_and(|mode| unsafe {
            SetConsoleMode(handle, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING) != 0
        });
        let color = interactive && std::env::var_os("NO_COLOR").is_none();
        Self {
            handle,
            mode,
            attributes,
            ansi,
            color,
            interactive,
        }
    }
    fn clear(&self, output: &mut impl Write) -> io::Result<()> {
        if self.ansi {
            write!(output, "\x1b[2J\x1b[H")?;
        } else if self.interactive {
            output.flush()?;
            let mut info = CONSOLE_SCREEN_BUFFER_INFO::default();
            if unsafe { GetConsoleScreenBufferInfo(self.handle, &mut info) } != 0 {
                let mut written = 0;
                for y in info.srWindow.Top..=info.srWindow.Bottom {
                    let position = COORD {
                        X: info.srWindow.Left,
                        Y: y,
                    };
                    let length = (info.srWindow.Right - info.srWindow.Left + 1) as u32;
                    unsafe {
                        FillConsoleOutputCharacterW(
                            self.handle,
                            b' ' as u16,
                            length,
                            position,
                            &mut written,
                        );
                        FillConsoleOutputAttribute(
                            self.handle,
                            info.wAttributes,
                            length,
                            position,
                            &mut written,
                        );
                    }
                }
                unsafe {
                    SetConsoleCursorPosition(
                        self.handle,
                        COORD {
                            X: info.srWindow.Left,
                            Y: info.srWindow.Top,
                        },
                    );
                }
            }
        }
        Ok(())
    }
    fn write(&self, output: &mut impl Write, text: &str, tone: Tone) -> io::Result<()> {
        if self.color {
            if self.ansi {
                write!(output, "{}", tone.ansi())?;
            } else if let Some(attributes) = self.attributes {
                output.flush()?;
                unsafe {
                    SetConsoleTextAttribute(self.handle, (attributes & !0x0f) | tone.classic());
                }
            }
        }
        write!(output, "{text}")
    }
    fn reset(&self, output: &mut impl Write) -> io::Result<()> {
        if self.ansi && self.color {
            write!(output, "\x1b[0m")?;
        }
        output.flush()?;
        if let Some(attributes) = self.attributes {
            unsafe {
                SetConsoleTextAttribute(self.handle, attributes);
            }
        }
        Ok(())
    }
}

impl Drop for Terminal {
    fn drop(&mut self) {
        // Restore the host's mode and palette even after an output error.
        if let Some(attributes) = self.attributes {
            unsafe {
                SetConsoleTextAttribute(self.handle, attributes);
            }
        }
        if let Some(mode) = self.mode {
            unsafe {
                SetConsoleMode(self.handle, mode);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn narrow_frames_keep_cyrillic_and_long_tokens_inside_the_border() {
        for columns in [8, 20, 24, 40, 54, 80, 160] {
            let viewport = Viewport { columns, rows: 30 };
            let mut frame = Frame::new(
                viewport,
                &format!("zapret-rust v{} · Настройки", crate::VERSION),
            );
            frame.item(10, "Проверка подключения и конфликтов", Tone::Text);
            let token = "ё".repeat(160);
            frame.row(&format!("  {token}"), Tone::Accent);
            let text = frame.plain();
            assert!(
                text.lines()
                    .all(|line| line.chars().count() == viewport.inner_width() + 2)
            );
            assert_eq!(text.matches('ё').count(), 160);
            assert!(!text.contains('\x1b'));
            assert!(text.ends_with("╯\n"));
        }
    }

    #[test]
    fn wrapping_preserves_words_and_continuation_indent() {
        assert_eq!(wrap("  Один два три", 12), ["  Один два", "    три"]);
        assert_eq!(wrap("  abcdefghij", 8), ["  abcdef", "    ghij"]);
        assert_eq!(wrap("", 8), [""]);
        assert_eq!(wrap("яюэ", 1), ["я", "ю", "э"]);
    }

    #[test]
    fn original_pink_and_lilac_accents_are_preserved() {
        assert_eq!(Tone::Accent.ansi(), "\x1b[38;2;255;209;232m");
        assert_eq!(Tone::Secondary.ansi(), "\x1b[38;2;223;192;255m");
        assert!(!wrap("a\x1b[31m", 20).join("").contains('\x1b'));
    }
}
