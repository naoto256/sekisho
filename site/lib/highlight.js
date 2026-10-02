// Build-time syntax highlighting for fenced code blocks.
//
// Deliberately small. Half the blocks in the docs are ```text — terminal
// transcripts and JSON responses that want no colour at all — and most of the
// rest are shell. A full grammar engine would be a large dependency and a
// large surface for mis-highlighting, in exchange for prettiness on a handful
// of blocks. This recognises three things per language (comments, strings,
// keywords) and leaves everything else alone.
//
// The three classes are the same ones the landing page's hand-marked listings
// use, so there is one palette to style and one set of contrast numbers.

const escape = (text) =>
  String(text).replace(
    /[&<>"']/g,
    (c) =>
      ({
        "&": "&amp;",
        "<": "&lt;",
        ">": "&gt;",
        '"': "&quot;",
        "'": "&#39;",
      })[c],
  );

// Each grammar is one alternation, scanned left to right. Ordering matters:
// a `#` inside a string must be part of the string, so the string branch has
// to be able to win — which it does, because whichever branch starts at the
// earlier offset is the one the scanner takes.
const STRING = `"(?:\\\\.|[^"\\\\])*"|'(?:\\\\.|[^'\\\\])*'`;

const GRAMMARS = {
  bash: {
    comment: /#[^\n]*/,
    string: new RegExp(STRING),
    keyword:
      /\b(?:if|then|else|elif|fi|for|while|do|done|case|esac|function|return|export|local|set|sudo|curl|systemctl|journalctl)\b/,
  },
  json: {
    string: new RegExp(STRING),
    keyword: /\b(?:true|false|null)\b|-?\b\d+(?:\.\d+)?\b/,
  },
  yaml: {
    comment: /#[^\n]*/,
    string: new RegExp(STRING),
    keyword: /\b(?:true|false|null|yes|no)\b/,
  },
  ini: {
    comment: /[#;][^\n]*/,
    string: new RegExp(STRING),
    keyword: /^\s*\[[^\]\n]*\]/m,
  },
  rust: {
    comment: /\/\/[^\n]*/,
    string: new RegExp(STRING),
    keyword:
      /\b(?:fn|let|mut|pub|use|struct|enum|impl|trait|match|if|else|for|while|loop|return|async|await|move|const|static|crate|self|Some|None|Ok|Err)\b/,
  },
  dockerfile: {
    comment: /#[^\n]*/,
    string: new RegExp(STRING),
    keyword:
      /^\s*(?:FROM|RUN|CMD|LABEL|EXPOSE|ENV|ADD|COPY|ENTRYPOINT|VOLUME|USER|WORKDIR|ARG|HEALTHCHECK)\b/m,
  },
};
GRAMMARS.sh = GRAMMARS.bash;
GRAMMARS.toml = GRAMMARS.ini;

const CLASS = { comment: "c", string: "s", keyword: "k" };

export function highlight(source, language) {
  const grammar = GRAMMARS[language];
  if (!grammar) return escape(source);

  // One combined pattern with named groups, so a single pass decides which
  // branch owns each offset instead of several passes fighting over it.
  const parts = Object.entries(grammar).map(
    ([kind, re]) => `(?<${kind}>${re.source})`,
  );
  const scanner = new RegExp(parts.join("|"), "gm");

  let out = "";
  let last = 0;
  for (const match of source.matchAll(scanner)) {
    const kind = Object.keys(match.groups).find(
      (k) => match.groups[k] !== undefined,
    );
    out += escape(source.slice(last, match.index));
    out += `<span class="${CLASS[kind]}">${escape(match[0])}</span>`;
    last = match.index + match[0].length;
  }
  return out + escape(source.slice(last));
}
