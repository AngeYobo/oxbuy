// SPDX-License-Identifier: MIT
/**
 * Brand / topic brief from a paid social-search response. Deterministic (no model call): the provider's JSON
 * schema is not documented, so posts are found by shape (objects carrying a text field) anywhere in the body.
 */

export type Post = { readonly text: string; readonly author?: string; readonly url?: string; readonly likes?: number };

const TEXT_KEYS = ["text", "full_text", "content", "body", "caption", "description"];
const AUTHOR_KEYS = ["author", "username", "screen_name", "user", "handle", "owner"];
const URL_KEYS = ["url", "link", "permalink", "tweet_url"];
const LIKE_KEYS = ["likes", "like_count", "favorite_count", "favourites_count", "likeCount"];

function pick(o: Record<string, unknown>, keys: string[]): unknown {
  for (const k of keys) if (o[k] !== undefined && o[k] !== null) return o[k];
  return undefined;
}

export function extractPosts(json: unknown, limit = 200): Post[] {
  const out: Post[] = [];
  const seen = new Set<string>();
  const visit = (v: unknown, depth: number) => {
    if (out.length >= limit || depth > 8 || v === null || typeof v !== "object") return;
    if (Array.isArray(v)) {
      for (const x of v) visit(x, depth + 1);
      return;
    }
    const o = v as Record<string, unknown>;
    const text = pick(o, TEXT_KEYS);
    if (typeof text === "string" && text.trim().length >= 3 && !seen.has(text)) {
      seen.add(text);
      const a = pick(o, AUTHOR_KEYS);
      const author = typeof a === "string" ? a : a && typeof a === "object" ? (pick(a as Record<string, unknown>, ["username", "screen_name", "name", "handle"]) as string | undefined) : undefined;
      const url = pick(o, URL_KEYS);
      const likes = pick(o, LIKE_KEYS);
      out.push({
        text: text.replace(/\s+/g, " ").trim(),
        ...(typeof author === "string" ? { author } : {}),
        ...(typeof url === "string" && /^https?:\/\//.test(url) ? { url } : {}),
        ...(typeof likes === "number" ? { likes } : {}),
      });
    }
    for (const x of Object.values(o)) if (typeof x === "object") visit(x, depth + 1);
  };
  visit(json, 0);
  return out;
}

const STOP = new Set(
  "the a an and or of to in on for with is are was were be been it its this that at by from as not but you your we our they their i me my he she his her them us so if just than then also have has had do does did will would can could should about into over more most very".split(" "),
);

export function topTerms(posts: readonly Post[], topic: string, n = 8): [string, number][] {
  const skip = new Set(topic.toLowerCase().split(/\W+/).filter(Boolean));
  const counts = new Map<string, number>();
  for (const p of posts) {
    const words = new Set(p.text.toLowerCase().replace(/https?:\/\/\S+/g, " ").split(/[^a-z0-9#@_]+/).filter((w) => w.length > 2 && !STOP.has(w) && !skip.has(w)));
    for (const w of words) counts.set(w, (counts.get(w) ?? 0) + 1);
  }
  return [...counts.entries()].sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0])).slice(0, n);
}

export type Brief = { readonly markdown: string; readonly posts: number };

export function buildBrief(input: { topic: string; posts: readonly Post[]; cost: string; tx?: string; explorer?: string; at: Date }): Brief {
  const { topic, posts } = input;
  const authors = new Map<string, number>();
  for (const p of posts) if (p.author) authors.set(p.author, (authors.get(p.author) ?? 0) + 1);
  const topAuthors = [...authors.entries()].sort((a, b) => b[1] - a[1]).slice(0, 5);
  const sample = [...posts].sort((a, b) => (b.likes ?? 0) - (a.likes ?? 0)).slice(0, 5);
  const lines = [
    `# OxBuy brief: ${topic}`,
    `_${input.at.toISOString().slice(0, 16).replace("T", " ")} UTC · ${posts.length} posts analysed_`,
    "",
    "## What people talk about",
    ...(posts.length ? topTerms(posts, topic).map(([w, c]) => `- **${w}** (${c})`) : ["- No posts found for this topic."]),
    "",
    "## Most active voices",
    ...(topAuthors.length ? topAuthors.map(([a, c]) => `- @${a.replace(/^@/, "")} (${c})`) : ["- n/a"]),
    "",
    "## Notable posts",
    ...sample.map((p) => `- ${p.author ? `@${p.author.replace(/^@/, "")}: ` : ""}${p.text.slice(0, 200)}${p.text.length > 200 ? "…" : ""}${p.url ? ` (${p.url})` : ""}`),
    "",
    "## Spend (authorized by OxDeAI)",
    `- ${input.cost}${input.tx ? ` · tx ${input.tx}` : ""}${input.explorer ? ` · ${input.explorer}` : ""}`,
  ];
  return { markdown: `${lines.join("\n")}\n`, posts: posts.length };
}
