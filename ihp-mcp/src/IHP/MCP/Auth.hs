{-# LANGUAGE OverloadedStrings #-}

-- | Bearer-token → user lookup for IHP apps, backed by the @api_tokens@ table
-- this package ships in @Schema.sql@.
--
-- This module deliberately uses raw 'unsafeSqlQuery' / 'unsafeSqlExec' rather
-- than IHP's typed @sqlQueryTyped@ or the @Generated.Types@ record API. Two
-- reasons:
--
--   1. A standalone library has no live DB attached at /its own/ compile time,
--      so @typedSql@'s Postgres introspection cannot run here.
--   2. It must not import the consuming app's @Generated.Types@ — those records
--      are generated per-app from the app's @Schema.sql@. By returning raw
--      'UUID's, the library stays decoupled and the app does its own
--      @fetch (Id userId)@ to get its own @User@ record.
--
-- This is exactly the "narrow case where typed SQL cannot work" the project's
-- SQL convention carves out.
module IHP.MCP.Auth
    ( lookupApiTokenUser
    ) where

import IHP.Prelude
import IHP.ModelSupport (ModelContext, unsafeSqlQuery, unsafeSqlExec)
import qualified Network.Wai as Wai
import Data.UUID (UUID)
import Database.PostgreSQL.Simple (Only (..))
import Database.PostgreSQL.Simple.Types (Binary (..))

import MCP.OAuth (hashToken)
import MCP.Protocol.Server (extractBearer)

-- | Resolve a request's bearer token to @(apiTokenId, userId)@, or 'Nothing'
-- if the header is missing, the token is unknown, revoked or expired.
--
-- Best-effort touches @last_used_at@. The caller maps @userId@ to its own
-- @User@ record (e.g. @fetch (Id userId)@) and packages whatever principal
-- 'MCP.Protocol.Server.McpServer' expects.
lookupApiTokenUser :: (?modelContext :: ModelContext) => Wai.Request -> IO (Maybe (UUID, UUID))
lookupApiTokenUser request =
    case extractBearer request of
        Nothing -> pure Nothing
        Just plaintext -> do
            let h = hashToken plaintext
            rows :: [(UUID, UUID)] <- unsafeSqlQuery
                "SELECT id, user_id FROM api_tokens \
                \WHERE token_hash = ? AND revoked_at IS NULL \
                \AND kind IN ('personal', 'oauth_access') \
                \AND (expires_at IS NULL OR expires_at > NOW()) \
                \LIMIT 1"
                (Only (Binary h))
            case rows of
                [] -> pure Nothing
                ((apiTokenId, userId) : _) -> do
                    -- Best-effort touch; ignore failures so a transient write
                    -- error doesn't 401 the request.
                    _ <- unsafeSqlExec "UPDATE api_tokens SET last_used_at = NOW() WHERE id = ?" (Only apiTokenId)
                    pure (Just (apiTokenId, userId))
