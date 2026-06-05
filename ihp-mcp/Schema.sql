-- ihp-mcp schema block.
--
-- IHP generates record types from each app's own Application/Schema.sql, and a
-- library cannot inject tables into that generated module. So adopting ihp-mcp
-- means pasting this block into your app's Application/Schema.sql (and running
-- the migration). The library's raw-SQL helpers target exactly these table and
-- column names.
--
-- Dependencies the host app must already provide:
--   * a `users` table with a UUID `id` (the FK target below)
--   * the `ihp_user_id()` function used by IHP row-level-security policies
--   * the `uuid-ossp` extension (uuid_generate_v4)

CREATE TABLE api_tokens (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY NOT NULL,
    user_id UUID NOT NULL,
    name TEXT NOT NULL,
    token_hash BYTEA NOT NULL UNIQUE,
    scope TEXT DEFAULT 'mcp_read' NOT NULL,
    kind TEXT NOT NULL DEFAULT 'personal',
    expires_at TIMESTAMP WITH TIME ZONE DEFAULT NULL,
    client_id TEXT DEFAULT NULL,
    parent_token_id UUID DEFAULT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW() NOT NULL,
    last_used_at TIMESTAMP WITH TIME ZONE DEFAULT NULL,
    revoked_at TIMESTAMP WITH TIME ZONE DEFAULT NULL
);
CREATE INDEX api_tokens_user_id_index ON api_tokens (user_id);
CREATE INDEX api_tokens_client_id_index ON api_tokens (client_id);
ALTER TABLE api_tokens ADD CONSTRAINT api_tokens_ref_user_id
    FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE;
ALTER TABLE api_tokens ADD CONSTRAINT api_tokens_ref_parent_token_id
    FOREIGN KEY (parent_token_id) REFERENCES api_tokens (id) ON DELETE SET NULL;
ALTER TABLE api_tokens ENABLE ROW LEVEL SECURITY;
CREATE POLICY api_tokens_user_policy ON api_tokens
    USING (user_id = ihp_user_id()) WITH CHECK (user_id = ihp_user_id());

CREATE TABLE oauth_clients (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY NOT NULL,
    client_id TEXT NOT NULL UNIQUE,
    client_name TEXT NOT NULL,
    redirect_uris TEXT[] NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW() NOT NULL,
    last_used_at TIMESTAMP WITH TIME ZONE DEFAULT NULL
);
ALTER TABLE oauth_clients ENABLE ROW LEVEL SECURITY;
CREATE POLICY "oauth_clients are public" ON oauth_clients USING (true) WITH CHECK (true);

CREATE TABLE oauth_authorization_codes (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY NOT NULL,
    code_hash BYTEA NOT NULL UNIQUE,
    client_id TEXT NOT NULL,
    user_id UUID NOT NULL,
    redirect_uri TEXT NOT NULL,
    code_challenge TEXT NOT NULL,
    code_challenge_method TEXT NOT NULL DEFAULT 'S256',
    scope TEXT NOT NULL DEFAULT 'mcp_read',
    resource TEXT DEFAULT NULL,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    consumed_at TIMESTAMP WITH TIME ZONE DEFAULT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW() NOT NULL
);
CREATE INDEX oauth_authorization_codes_expires_at_index ON oauth_authorization_codes (expires_at);
ALTER TABLE oauth_authorization_codes ADD CONSTRAINT oauth_authorization_codes_ref_user_id
    FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE;
ALTER TABLE oauth_authorization_codes ENABLE ROW LEVEL SECURITY;
CREATE POLICY "oauth_authorization_codes are public" ON oauth_authorization_codes USING (true) WITH CHECK (true);
