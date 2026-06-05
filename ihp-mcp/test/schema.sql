-- Minimal schema for the ihp-mcp test-suite. The real Schema.sql adds RLS
-- policies (which assume ihp_user_id() + an authenticated role); the test owns
-- its tables and connects as the table owner, so RLS is omitted here.
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

CREATE TABLE users (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY NOT NULL
);

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

CREATE TABLE oauth_clients (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY NOT NULL,
    client_id TEXT NOT NULL UNIQUE,
    client_name TEXT NOT NULL,
    redirect_uris TEXT[] NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW() NOT NULL,
    last_used_at TIMESTAMP WITH TIME ZONE DEFAULT NULL
);

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
