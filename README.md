# ihp-mcp

A reusable [Model Context Protocol](https://modelcontextprotocol.io) server for
IHP applications, extracted from near-identical hand-rolled MCP servers across
two production IHP apps. Two layers:

| Package | Depends on | What it is |
|---|---|---|
| **`mcp-server`** | aeson, wai, crypton — **no framework** | JSON-RPC 2.0 / Streamable-HTTP transport, the `Tool` abstraction, OAuth 2.1 token + PKCE primitives, RFC 9728/8414 discovery metadata. Reusable from Servant or bare-WAI too. |
| **`ihp-mcp`** | `mcp-server` + `ihp` | IHP storage glue: bearer-token auth and the OAuth authorization server, backed by the `api_tokens` / `oauth_*` tables in [`Schema.sql`](ihp-mcp/Schema.sql). Uses raw SQL so it never imports the host app's `Generated.Types`. |

## Why two layers

The two source apps shared ~400–700 LOC of byte-identical MCP boilerplate
(JSON-RPC types, error codes, OAuth/PKCE, well-known metadata, dispatch loop).
That duplication is the cost; the win is also a single place to bump the
protocol version and add features (resources, prompts, SSE streaming) instead
of editing two copies in lockstep.

The split is dictated by one hard constraint: **a flake-input library can't see
the app's `Generated.Types`** (`User`, `ApiToken`, `OauthClient`, …), which IHP
generates per-app from `Application/Schema.sql`. So everything that touches
those records is either kept app-side or rewritten against fixed table names
with raw SQL. That cleaves the code exactly along the `mcp-server` / `ihp-mcp`
line.

## Using it (IHP app)

1. **Schema** — paste [`ihp-mcp/Schema.sql`](ihp-mcp/Schema.sql) into your
   app's `Application/Schema.sql` and migrate. (Requires a `users` table with a
   UUID `id`, the `ihp_user_id()` RLS helper, and `uuid-ossp`.) This is the one
   manual step — IHP can't auto-inject library schema.

2. **MCP endpoint** — build an `McpServer` and serve it from your `/mcp` route:

   ```haskell
   import qualified MCP.Protocol.Server as Mcp
   import qualified IHP.MCP.Auth as Mcp.Auth

   mcpServer :: (?modelContext :: ModelContext) => Mcp.McpServer User
   mcpServer = (Mcp.defaultMcpServer "myapp-mcp" "0.1.0" authenticate tools)
       { Mcp.withScope     = \user -> withRowLevelSecurity user   -- optional
       , Mcp.resolveIssuer = WellKnown.resolveIssuer "myapp.example"
       }
     where
       authenticate request = do
           row <- Mcp.Auth.lookupApiTokenUser request   -- Maybe (apiTokenId, userId)
           forM row \(_, userId) -> fetch (Id userId)    -- app maps to its own User
       tools _request user =
           [ Mcp.Tool { name = "run_sql", description = "…", inputSchema = …
                      , handler = \args -> TextResult <$> runSql user args }
           , …
           ]

   -- Web/Controller/Mcp.hs
   action McpAction = do
       body <- getRequestBody
       respondAndExit =<< liftIO (Mcp.handleMcpRequest mcpServer ?request body)
   ```

   A tool's `handler :: Value -> IO ToolResult` closes over the authenticated
   user and the model context — the core never sees them. `ToolResult` is
   `TextResult` / `ErrorResult` / `RawResult` (the last for pre-built content
   like image blocks).

3. **OAuth** — wire `IHP.MCP.OAuth.Endpoints` into your `Register` / `Token`
   controllers (one-liners; the handlers take the raw request body):

   ```haskell
   action RegisterClientAction = respondAndExit =<< liftIO . OAuth.handleRegister =<< getRequestBody
   action TokenAction          = respondAndExit =<< liftIO . OAuth.handleToken    =<< getRequestBody
   ```

   The `Authorize` endpoint stays a thin **app** controller — it needs the
   app's login session (`currentUserOrNothing`, `setSession`, `redirectToPath`)
   and renders the app's own branded consent view. After the user approves, it
   calls `OAuth.mintAuthorizationCode` to persist the code and gets back the
   plaintext to embed in the redirect.

4. **Well-known routes** — serve `MCP.OAuth.WellKnown.{protectedResourceMetadata,
   authorizationServerMetadata}` from `/.well-known/oauth-protected-resource[/mcp]`
   and `/.well-known/oauth-authorization-server` (wire in `FrontController`, as
   today).

## Consuming it from an IHP app's `flake.nix`

Add it as a source flake input and `callCabal2nix` each package — the usual
pattern for IHP-app Haskell deps (these libs ship **without** their own flake):

```nix
inputs.ihp-mcp = { url = "git+ssh://git@github.com/digitallyinduced/ihp-mcp?ref=main"; flake = false; };

# devenv overlay:
ghc = prev.ghc.extend (hself: _: {
    mcp-server = hself.callCabal2nix "mcp-server" "${inputs.ihp-mcp}/mcp-server" {};
    ihp-mcp    = hself.callCabal2nix "ihp-mcp"    "${inputs.ihp-mcp}/ihp-mcp"    {};
});

# haskellPackages = p: with p; [ ... mcp-server ihp-mcp ... ];
```

## Status

- [x] **Phase 1** — `mcp-server` core (`MCP.Protocol.{Types,Tool,Server}`, `MCP.OAuth`, `MCP.OAuth.WellKnown`).
- [x] **Phase 2** — `ihp-mcp` glue: `IHP.MCP.Auth` (bearer lookup) + `IHP.MCP.OAuth.Endpoints` (Register/Token raw-SQL, PKCE-S256, refresh rotation + reuse detection) + `mintAuthorizationCode` + `Schema.sql`.
- [x] **Phase 3** — first production IHP app migrated onto the packages (net −566 LOC), deployed and verified live: GET probe, unauthenticated 401 challenge, well-known metadata, and authenticated `initialize` / `tools/list` / `tools/call` (both success + error envelopes).
- [ ] **Phase 4** — migrate a second app, verify, deploy.

> **Verified:** all 7 modules typecheck against a production IHP app's real
> toolchain (IHP 1.5.0 / hasql 1.10 / aeson 2.2 / GHC 9.10) via `ghc -fno-code`
> with that app's extension set. No standalone `flake.nix` — consumed flake-less
> via `callCabal2nix`, like other IHP-app source deps.
