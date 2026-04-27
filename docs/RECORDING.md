# Recording demo GIFs

Lightweight workflow for capturing the `mcp-fs-agent` live demo as a
GIF for the README. The same flow works for any of the other example
demos — substitute the npm command.

## Prerequisites

- Windows + ScreenToGif or OBS (or macOS + QuickTime, or Linux +
  `peek` / `byzanz` — anything that produces a video file).
- ffmpeg on PATH for the `.mp4 → .gif` conversion.
- A clean terminal: 100×30, dark background, no system status line.

## Steps

1. **Pre-warm the npx fetch** so the GIF doesn't show the
   `@modelcontextprotocol/server-filesystem` download progress:

   ```bash
   npx -y @modelcontextprotocol/server-filesystem --version 2>nul
   ```

   (Or just run the demo once before recording — npx caches the
   package after the first run.)

2. **Clear the terminal** and start the screen recorder.

3. **Run the demo:**

   ```bash
   npm run -w @capnagent-examples/mcp-fs-agent demo:live-mcp
   ```

   Recording target length: ~8–12 seconds. The demo runs ~5 seconds
   end-to-end after the npx cache is warm; everything else is the
   text staying on screen long enough to read.

4. **Stop the recording** as soon as the result block appears (the
   `tools that reached the MCP server: ["read_text_file","list_directory"]`
   line is the natural payoff frame).

5. **Save the source video** somewhere temporary, e.g.
   `C:\Users\<you>\Videos\capnagent-live-mcp.mp4`.

6. **Convert to GIF** via ffmpeg. Two-pass to keep the file size
   reasonable while preserving the ANSI colors:

   ```bash
   ffmpeg -i C:/Users/<you>/Videos/capnagent-live-mcp.mp4 \
     -vf "fps=12,scale=900:-1:flags=lanczos,palettegen=stats_mode=full" \
     -y palette.png

   ffmpeg -i C:/Users/<you>/Videos/capnagent-live-mcp.mp4 \
     -i palette.png \
     -lavfi "fps=12,scale=900:-1:flags=lanczos[x];[x][1:v]paletteuse=dither=bayer:bayer_scale=5" \
     -y docs/demo-live-mcp.gif
   ```

   Target file size: under 3 MB. If larger, drop `fps` to 10 or
   `scale` to 800.

7. **Update the README** to reference the new GIF in the "Quick taste"
   or examples section.

8. **Commit** the GIF:

   ```bash
   git add docs/demo-live-mcp.gif README.md
   git commit -m "docs: live-MCP demo GIF"
   git push
   ```

## What the GIF should show

The visual story in 8 seconds:

- Header: "capnagent live-MCP fs-agent demo" + sandbox/outside paths.
- Step 1 + 2: green ✓ allowed, with body preview.
- Step 3: green ✓ denied for the OUTSIDE read — note the demo's label
  explicitly says "server CAN reach it; capnagent denies." This is
  the punchy frame: even though the server is configured to allow
  the path, the call never gets there.
- Step 4: green ✓ denied for write_file.
- Result line: `tools that reached the MCP server: ["read_text_file","list_directory"]`.

The point of the GIF: only the in-scope reads reached the real server.
Everything else was caught at the capability boundary.
