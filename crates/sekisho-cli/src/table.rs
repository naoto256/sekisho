//! Small text-table formatter for `show` listings that need to render
//! more than a single label per row.
//!
//! Plain ASCII output — no ANSI colors, no Unicode box drawing — so the
//! result stays readable in piped output (`sekisho-cli show sessions |
//! grep alice`) and matches the rest of the CLI's "boring text" tone.
//! Column widths are computed from the data (header + every cell), then
//! every row is padded with two spaces between columns. The trailing
//! column is not padded so wide cells don't trail blanks.
//!
//! Today this is consumed by `show sessions`; future rich listings
//! (e.g. routes with status + upstream count) can re-use it instead of
//! growing yet another bespoke loop.

/// Render `headers` + `rows` as a left-aligned table. Every row must
/// have the same number of cells as `headers`; mismatched rows are
/// silently truncated/padded so a malformed cell doesn't panic at the
/// operator's terminal.
pub fn render(headers: &[&str], rows: &[Vec<String>]) -> String {
    let cols = headers.len();
    if cols == 0 {
        return String::new();
    }
    let mut widths: Vec<usize> = headers.iter().map(|h| h.len()).collect();
    for row in rows {
        for (i, cell) in row.iter().enumerate().take(cols) {
            if cell.len() > widths[i] {
                widths[i] = cell.len();
            }
        }
    }

    let mut out = String::new();
    write_row(&mut out, headers.iter().copied(), &widths);
    for row in rows {
        // Normalize row length so row[i] is always defined for i < cols.
        let cells = (0..cols).map(|i| row.get(i).map(String::as_str).unwrap_or(""));
        write_row(&mut out, cells, &widths);
    }
    out
}

fn write_row<'a>(out: &mut String, cells: impl Iterator<Item = &'a str>, widths: &[usize]) {
    let cells: Vec<&str> = cells.collect();
    let last = cells.len().saturating_sub(1);
    for (i, cell) in cells.iter().enumerate() {
        if i == last {
            // Don't pad the trailing column — keeps line length minimal.
            out.push_str(cell);
        } else {
            out.push_str(cell);
            // Pad to column width plus a 2-space gutter.
            let pad = widths[i].saturating_sub(cell.len()) + 2;
            for _ in 0..pad {
                out.push(' ');
            }
        }
    }
    out.push('\n');
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_headers_yields_empty_string() {
        assert_eq!(render(&[], &[]), "");
    }

    #[test]
    fn header_only_renders_header_line() {
        let out = render(&["A", "B"], &[]);
        assert_eq!(out, "A  B\n");
    }

    #[test]
    fn columns_pad_to_widest_cell() {
        let out = render(
            &["X", "Y"],
            &[
                vec!["short".into(), "1".into()],
                vec!["longer-cell".into(), "2".into()],
            ],
        );
        // "longer-cell" sets column 0's width (11), so "short" pads to
        // 11 + 2 spaces of gutter.
        assert_eq!(out, "X            Y\nshort        1\nlonger-cell  2\n");
    }

    #[test]
    fn missing_cells_render_as_blank() {
        let out = render(&["A", "B"], &[vec!["only-a".into()]]);
        assert_eq!(out, "A       B\nonly-a  \n");
    }
}
