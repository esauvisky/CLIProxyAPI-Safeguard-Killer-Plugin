# Agent instructions

## No workarounds for things the user controls in the client

Never add plugin behavior that counteracts a client-side limit or preference the user can change in the client itself (Claude Code settings, environment variables, `/config`, output styles, tool parameters). Examples of what not to do:

- Appending hints to Read results because Claude Code caps Read output, when `CLAUDE_CODE_FILE_READ_MAX_OUTPUT_TOKENS` raises the cap.
- Replacing the client's output-style reminders with the plugin's own style directive, when the user picks the output style in Claude Code.

When such a limit gets in the way, tell the user which client setting solves it instead of patching around it in the proxy. The plugin should not inject its own prompts or instructions to compensate for client configuration.
