{-# LANGUAGE OverloadedStrings #-}

-- | OAuth 2.0 discovery metadata (RFC 9728 / RFC 8414) and issuer resolution.
--
-- Pure functions over @Text@ + a thin @Wai.Request@ reader. The @ihp-mcp@
-- glue serves these from the app's @\/.well-known\/...@ routes.
module MCP.OAuth.WellKnown
    ( resolveIssuer
    , protectedResourceMetadata
    , authorizationServerMetadata
    ) where

import Prelude
import Data.Aeson
import Data.Text (Text)
import qualified Data.Text.Encoding as TextEnc
import qualified Network.Wai as Wai

-- | Resolve the issuer URL (@scheme://host@) from the request. Trusts
-- @X-Forwarded-Proto@ / @Host@ so the values match what the customer sees in
-- their browser. @fallbackHost@ is used only when the @Host@ header is absent
-- (effectively never for a real MCP client).
resolveIssuer :: Text -> Wai.Request -> Text
resolveIssuer fallbackHost request =
    let host = case lookup "Host" (Wai.requestHeaders request) of
            Just h -> TextEnc.decodeUtf8 h
            Nothing -> fallbackHost
        scheme = case lookup "X-Forwarded-Proto" (Wai.requestHeaders request) of
            Just s -> TextEnc.decodeUtf8 s
            Nothing -> if Wai.isSecure request then "https" else "http"
    in scheme <> "://" <> host

-- | RFC 9728 OAuth 2.0 Protected Resource Metadata. This is what Claude.ai
-- fetches first after seeing our @WWW-Authenticate@ challenge.
protectedResourceMetadata :: Text -> Value
protectedResourceMetadata issuerUrl = object
    [ "resource" .= (issuerUrl <> "/mcp")
    , "authorization_servers" .= ([issuerUrl] :: [Text])
    , "bearer_methods_supported" .= (["header"] :: [Text])
    , "scopes_supported" .= (["mcp_read"] :: [Text])
    ]

-- | RFC 8414 Authorization Server Metadata. Endpoint paths
-- (@\/Authorize@, @\/Token@, @\/Register@) match the routes the @ihp-mcp@
-- glue installs.
authorizationServerMetadata :: Text -> Value
authorizationServerMetadata issuerUrl = object
    [ "issuer" .= issuerUrl
    , "authorization_endpoint" .= (issuerUrl <> "/Authorize")
    , "token_endpoint" .= (issuerUrl <> "/Token")
    , "registration_endpoint" .= (issuerUrl <> "/Register")
    , "response_types_supported" .= (["code"] :: [Text])
    , "grant_types_supported" .= (["authorization_code", "refresh_token"] :: [Text])
    , "code_challenge_methods_supported" .= (["S256"] :: [Text])
    , "token_endpoint_auth_methods_supported" .= (["none"] :: [Text])
    , "scopes_supported" .= (["mcp_read"] :: [Text])
    ]
