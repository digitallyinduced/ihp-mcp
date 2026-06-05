{-# LANGUAGE OverloadedStrings #-}

-- | The OAuth 2.1 authorization-server endpoints that have no UI: Dynamic
-- Client Registration (RFC 7591) and the token endpoint (RFC 6749
-- @authorization_code@ + @refresh_token@ grants, PKCE-S256).
--
-- Each handler takes the raw request body and returns a ready 'Wai.Response',
-- so the host app's controller is a one-liner:
--
-- > action RegisterClientAction = respondAndExit =<< liftIO . OAuth.handleRegister =<< getRequestBody
-- > action TokenAction          = respondAndExit =<< liftIO . OAuth.handleToken    =<< getRequestBody
--
-- Like "IHP.MCP.Auth", everything is raw SQL (via @unsafeSqlQuery@ /
-- @unsafeSqlExec@) against the fixed @oauth_*@ / @api_tokens@ tables (see
-- @Schema.sql@) so this never imports the app's @Generated.Types@. The
-- @\/Authorize@ endpoint is /not/ here: it needs the app's login session and
-- renders the app's branded consent screen, so it stays an app controller that
-- calls 'mintAuthorizationCode'.
module IHP.MCP.OAuth.Endpoints
    ( handleRegister
    , handleToken
    , mintAuthorizationCode
    ) where

import IHP.Prelude
import IHP.ModelSupport (ModelContext, unsafeSqlQuery, unsafeSqlExec)
import IHP.Hasql.FromRow (FromRowHasql (..), HasqlDecodeColumn (..))
import qualified Data.Aeson as Aeson
import Data.Aeson ((.:?), (.!=), (.=), object)
import qualified Data.ByteString.Lazy as LBS
import qualified Data.Text as Text
import qualified Data.Text.Encoding as TextEnc
import qualified Network.Wai as Wai
import qualified Network.HTTP.Types as HTTP
import qualified Network.HTTP.Types.URI as URI
import Data.UUID (UUID)
import Database.PostgreSQL.Simple (Only (..))
import Database.PostgreSQL.Simple.Types (Binary (..))
import Data.Time.Clock (UTCTime, getCurrentTime, addUTCTime, secondsToNominalDiffTime)
import Data.Time.Clock.POSIX (utcTimeToPOSIXSeconds)

import qualified MCP.OAuth as OAuth

------------------------------------------------------------
-- /Register — RFC 7591 Dynamic Client Registration (public clients)
------------------------------------------------------------

handleRegister :: (?modelContext :: ModelContext) => LBS.ByteString -> IO Wai.Response
handleRegister body =
    case Aeson.eitherDecode body of
        Left err -> pure $ jsonErr HTTP.status400 "invalid_client_metadata" (cs err)
        Right (RegisterRequest { redirectUris, clientName })
            | null redirectUris -> pure $ jsonErr HTTP.status400 "invalid_redirect_uri" "redirect_uris must be non-empty"
            | otherwise -> do
                clientId <- OAuth.generateClientId
                let name = if Text.null clientName then "Unnamed client" else clientName
                _ <- unsafeSqlExec
                    "INSERT INTO oauth_clients (client_id, client_name, redirect_uris) VALUES (?, ?, ?)"
                    (clientId, name, redirectUris)
                now <- getCurrentTime
                pure $ jsonOk HTTP.status201 $ object
                    [ "client_id" .= clientId
                    , "client_id_issued_at" .= (floor (utcTimeToPOSIXSeconds now) :: Integer)
                    , "client_name" .= name
                    , "redirect_uris" .= redirectUris
                    , "token_endpoint_auth_method" .= ("none" :: Text)
                    , "grant_types" .= (["authorization_code", "refresh_token"] :: [Text])
                    , "response_types" .= (["code"] :: [Text])
                    , "scope" .= ("mcp_read" :: Text)
                    ]

------------------------------------------------------------
-- /Token — authorization_code + refresh_token grants
------------------------------------------------------------

handleToken :: (?modelContext :: ModelContext) => LBS.ByteString -> IO Wai.Response
handleToken body =
    let params = parseForm body
    in case formParam "grant_type" params of
        "authorization_code" -> handleAuthCodeGrant params
        "refresh_token" -> handleRefreshGrant params
        _ -> pure $ jsonErr HTTP.status400 "unsupported_grant_type" "must be authorization_code or refresh_token"

-- | A persisted authorization code, selected by its hash.
data AuthCodeRow = AuthCodeRow
    { acClientId :: !Text
    , acUserId :: !UUID
    , acRedirectUri :: !Text
    , acCodeChallenge :: !Text
    , acScope :: !Text
    , acExpiresAt :: !UTCTime
    , acConsumedAt :: !(Maybe UTCTime)
    }

instance FromRowHasql AuthCodeRow where
    hasqlRowDecoder = AuthCodeRow
        <$> hasqlColumnDecoder <*> hasqlColumnDecoder <*> hasqlColumnDecoder
        <*> hasqlColumnDecoder <*> hasqlColumnDecoder <*> hasqlColumnDecoder
        <*> hasqlColumnDecoder

handleAuthCodeGrant :: (?modelContext :: ModelContext) => [(Text, Text)] -> IO Wai.Response
handleAuthCodeGrant params = do
    let code = formParam "code" params
        codeVerifier = formParam "code_verifier" params
        clientId = formParam "client_id" params
        redirectUri = formParam "redirect_uri" params
    if Text.null code then pure (jsonErr HTTP.status400 "invalid_request" "code required")
    else if Text.null codeVerifier then pure (jsonErr HTTP.status400 "invalid_request" "code_verifier required")
    else do
        let h = OAuth.hashToken code
        rows :: [AuthCodeRow] <- unsafeSqlQuery
            "SELECT client_id, user_id, redirect_uri, code_challenge, scope, expires_at, consumed_at \
            \FROM oauth_authorization_codes WHERE code_hash = ? LIMIT 1"
            (Only (Binary h))
        case rows of
            [] -> pure $ jsonErr HTTP.status400 "invalid_grant" "code not found"
            (row : _) -> do
                now <- getCurrentTime
                let badGrant = pure . jsonErr HTTP.status400 "invalid_grant"
                if isJust row.acConsumedAt then do
                    -- Replay of an already-used code: revoke any tokens the
                    -- first exchange minted, then reject. (Defense in depth.)
                    _ <- unsafeSqlExec
                        "UPDATE api_tokens SET revoked_at = NOW() WHERE client_id = ? AND created_at >= ? AND revoked_at IS NULL"
                        (row.acClientId, row.acExpiresAt)
                    badGrant "code already used"
                else if row.acExpiresAt <= now then badGrant "code expired"
                else if row.acClientId /= clientId then badGrant "client_id mismatch"
                else if row.acRedirectUri /= redirectUri then badGrant "redirect_uri mismatch"
                else if not (OAuth.verifyPkceS256 codeVerifier row.acCodeChallenge) then badGrant "PKCE verification failed"
                else do
                    _ <- unsafeSqlExec
                        "UPDATE oauth_authorization_codes SET consumed_at = ? WHERE code_hash = ?"
                        (now, Binary h)
                    (accessPlain, refreshPlain) <- issueTokenPair row.acUserId row.acClientId row.acScope now
                    pure $ tokenResponse accessPlain refreshPlain row.acScope

-- | A refresh-token row, selected by its hash.
data RefreshRow = RefreshRow
    { rfId :: !UUID
    , rfUserId :: !UUID
    , rfClientId :: !(Maybe Text)
    , rfScope :: !Text
    , rfExpiresAt :: !(Maybe UTCTime)
    , rfRevokedAt :: !(Maybe UTCTime)
    , rfParentTokenId :: !(Maybe UUID)
    }

instance FromRowHasql RefreshRow where
    hasqlRowDecoder = RefreshRow
        <$> hasqlColumnDecoder <*> hasqlColumnDecoder <*> hasqlColumnDecoder
        <*> hasqlColumnDecoder <*> hasqlColumnDecoder <*> hasqlColumnDecoder
        <*> hasqlColumnDecoder

handleRefreshGrant :: (?modelContext :: ModelContext) => [(Text, Text)] -> IO Wai.Response
handleRefreshGrant params = do
    let refreshToken = formParam "refresh_token" params
        clientId = formParam "client_id" params
    if Text.null refreshToken then pure (jsonErr HTTP.status400 "invalid_request" "refresh_token required")
    else do
        let h = OAuth.hashToken refreshToken
        rows :: [RefreshRow] <- unsafeSqlQuery
            "SELECT id, user_id, client_id, scope, expires_at, revoked_at, parent_token_id \
            \FROM api_tokens WHERE token_hash = ? AND kind = 'oauth_refresh' LIMIT 1"
            (Only (Binary h))
        case rows of
            [] -> pure $ jsonErr HTTP.status400 "invalid_grant" "refresh token not found"
            (row : _) -> do
                now <- getCurrentTime
                let badGrant = pure . jsonErr HTTP.status400 "invalid_grant"
                if isJust row.rfRevokedAt then do
                    -- Reuse of a revoked refresh token ⇒ revoke the whole family.
                    forM_ row.rfParentTokenId \pid ->
                        unsafeSqlExec "UPDATE api_tokens SET revoked_at = NOW() WHERE id = ? OR parent_token_id = ?" (pid, pid)
                    badGrant "refresh token reused"
                else case row.rfExpiresAt of
                    Just t | t <= now -> badGrant "refresh token expired"
                    _ | row.rfClientId /= Just clientId -> badGrant "client_id mismatch"
                    _ -> do
                        _ <- unsafeSqlExec "UPDATE api_tokens SET revoked_at = NOW() WHERE id = ?" (Only row.rfId)
                        forM_ row.rfParentTokenId \pid ->
                            unsafeSqlExec "UPDATE api_tokens SET revoked_at = NOW() WHERE id = ?" (Only pid)
                        (accessPlain, refreshPlain) <- issueTokenPair row.rfUserId clientId row.rfScope now
                        pure $ tokenResponse accessPlain refreshPlain row.rfScope

-- | Mint an access + refresh pair, persisting hashes. The refresh row points
-- at the access row via @parent_token_id@ so reuse detection can revoke the
-- whole family. Returns the two plaintext tokens.
issueTokenPair :: (?modelContext :: ModelContext) => UUID -> Text -> Text -> UTCTime -> IO (Text, Text)
issueTokenPair userId clientId scope now = do
    (accessPlain, accessHash) <- OAuth.generateAccessToken
    (refreshPlain, refreshHash) <- OAuth.generateRefreshToken
    let accessExpires = addUTCTime (secondsToNominalDiffTime (fromIntegral OAuth.accessTokenLifetimeSeconds)) now
        refreshExpires = addUTCTime (secondsToNominalDiffTime (fromIntegral OAuth.refreshTokenLifetimeSeconds)) now

    accessIds :: [Only UUID] <- unsafeSqlQuery
        "INSERT INTO api_tokens (user_id, name, token_hash, scope, kind, expires_at, client_id) \
        \VALUES (?, ?, ?, ?, 'oauth_access', ?, ?) RETURNING id"
        (userId, "OAuth access for " <> clientId, Binary accessHash, scope, accessExpires, clientId)
    let accessId = case accessIds of
            (Only i : _) -> i
            _ -> error "ihp-mcp: INSERT ... RETURNING id produced no row"

    _ <- unsafeSqlExec
        "INSERT INTO api_tokens (user_id, name, token_hash, scope, kind, expires_at, client_id, parent_token_id) \
        \VALUES (?, ?, ?, ?, 'oauth_refresh', ?, ?, ?)"
        ( userId, "OAuth refresh for " <> clientId, Binary refreshHash, scope
        , refreshExpires, clientId, accessId )

    pure (accessPlain, refreshPlain)

-- | Persist an authorization code for the @\/Authorize@ consent step. The
-- app's controller calls this after the user approves; it owns the login
-- check, the consent view and the final redirect. Returns the plaintext code
-- to embed in the redirect URI.
mintAuthorizationCode
    :: (?modelContext :: ModelContext)
    => Text       -- ^ client_id
    -> UUID       -- ^ approving user id
    -> Text       -- ^ redirect_uri
    -> Text       -- ^ code_challenge (S256)
    -> Text       -- ^ scope
    -> IO Text
mintAuthorizationCode clientId userId redirectUri codeChallenge scope = do
    (codePlaintext, codeHash) <- OAuth.generateAuthCode
    now <- getCurrentTime
    let expiresAt = addUTCTime (secondsToNominalDiffTime (fromIntegral OAuth.authCodeLifetimeSeconds)) now
    _ <- unsafeSqlExec
        "INSERT INTO oauth_authorization_codes \
        \(code_hash, client_id, user_id, redirect_uri, code_challenge, code_challenge_method, scope, expires_at) \
        \VALUES (?, ?, ?, ?, ?, 'S256', ?, ?)"
        ( Binary codeHash, clientId, userId, redirectUri, codeChallenge, scope, expiresAt )
    pure codePlaintext

------------------------------------------------------------
-- DCR request body
------------------------------------------------------------

data RegisterRequest = RegisterRequest
    { redirectUris :: ![Text]
    , clientName :: !Text
    }

instance Aeson.FromJSON RegisterRequest where
    parseJSON = Aeson.withObject "RegisterRequest" \v -> do
        redirectUris <- v .:? "redirect_uris" .!= []
        clientName <- v .:? "client_name" .!= ""
        pure RegisterRequest { redirectUris, clientName }

------------------------------------------------------------
-- Form-body + response helpers
------------------------------------------------------------

-- | Parse an @application/x-www-form-urlencoded@ body into decoded text pairs.
parseForm :: LBS.ByteString -> [(Text, Text)]
parseForm body =
    [ (TextEnc.decodeUtf8 k, maybe "" TextEnc.decodeUtf8 v)
    | (k, v) <- URI.parseQuery (LBS.toStrict body)
    ]

formParam :: Text -> [(Text, Text)] -> Text
formParam k params = fromMaybe "" (lookup k params)

tokenResponse :: Text -> Text -> Text -> Wai.Response
tokenResponse accessPlain refreshPlain scope = jsonOk HTTP.status200 $ object
    [ "access_token" .= accessPlain
    , "token_type" .= ("Bearer" :: Text)
    , "expires_in" .= OAuth.accessTokenLifetimeSeconds
    , "refresh_token" .= refreshPlain
    , "scope" .= scope
    ]

jsonOk :: HTTP.Status -> Aeson.Value -> Wai.Response
jsonOk status v = Wai.responseLBS status
    [(HTTP.hContentType, "application/json"), ("Cache-Control", "no-store")]
    (Aeson.encode v)

jsonErr :: HTTP.Status -> Text -> Text -> Wai.Response
jsonErr status err desc = Wai.responseLBS status
    [(HTTP.hContentType, "application/json"), ("Cache-Control", "no-store")]
    (Aeson.encode (object [ "error" .= err, "error_description" .= desc ]))
