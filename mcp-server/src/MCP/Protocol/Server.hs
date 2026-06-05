{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE DuplicateRecordFields #-}
{-# LANGUAGE OverloadedRecordDot #-}
{-# LANGUAGE ScopedTypeVariables #-}

-- | The MCP HTTP transport: a Streamable-HTTP / JSON-RPC 2.0 server over WAI.
--
-- The server is parameterized over an app-defined principal @p@ (whatever
-- @authenticate@ produces — typically an authenticated user plus token id).
-- The core knows nothing about how @p@ is obtained or what a tool does; it
-- only routes JSON-RPC methods and wraps results. Everything app-specific is
-- supplied through 'McpServer'.
module MCP.Protocol.Server
    ( McpServer (..)
    , defaultMcpServer
    , handleMcpRequest
    , extractBearer
    ) where

import Prelude
import Control.Exception (SomeException)
import qualified Control.Exception as Exception
import Data.Aeson
import qualified Data.Aeson as Aeson
import qualified Data.Aeson.Key as AesonKey
import qualified Data.Aeson.KeyMap as KM
import qualified Data.ByteString.Lazy as LBS
import Data.List (find)
import Data.Maybe (fromMaybe)
import Data.Text (Text)
import qualified Data.Text as Text
import qualified Data.Text.Encoding as TextEnc
import qualified Network.HTTP.Types as HTTP
import qualified Network.Wai as Wai

import MCP.Protocol.Tool
import MCP.Protocol.Types
import qualified MCP.OAuth.WellKnown as WellKnown

-- | Everything the transport needs from the embedding application.
data McpServer p = McpServer
    { serverName :: !Text
      -- ^ Advertised in @serverInfo@ and the @GET /mcp@ probe response.
    , serverVersion :: !Text
    , authenticate :: Wai.Request -> IO (Maybe p)
      -- ^ Resolve the bearer credential to a principal. 'Nothing' ⇒ 401 +
      -- @WWW-Authenticate@ challenge (which triggers the OAuth dance in
      -- Claude.ai / Claude Code).
    , tools :: Wai.Request -> p -> [Tool]
      -- ^ The tools available to this principal. Receives the request so a
      -- tool can close over e.g. the @Host@ header (for building URLs).
    , withScope :: p -> IO JsonRpcResponse -> IO JsonRpcResponse
      -- ^ Wrap @tools/call@ execution — e.g. bind a Postgres row-level-security
      -- context for the principal. A polymorphic wrapper such as
      -- @withRowLevelSecurity user :: IO a -> IO a@ unifies here. Defaults to a
      -- no-op in 'defaultMcpServer'.
    , resolveIssuer :: Wai.Request -> Text
      -- ^ Issuer URL used in the @WWW-Authenticate@ challenge. Defaults to
      -- the @Host@ header with a @localhost@ fallback.
    }

-- | An 'McpServer' with sensible defaults: no scope wrapping, issuer resolved
-- from the @Host@ header. Supply name, version, auth and tools.
defaultMcpServer
    :: Text
    -> Text
    -> (Wai.Request -> IO (Maybe p))
    -> (Wai.Request -> p -> [Tool])
    -> McpServer p
defaultMcpServer name version auth toolsFn = McpServer
    { serverName = name
    , serverVersion = version
    , authenticate = auth
    , tools = toolsFn
    , withScope = \_ io -> io
    , resolveIssuer = WellKnown.resolveIssuer "localhost"
    }

-- | Top-level entry point. Returns a fully-formed 'Wai.Response'. Wire this to
-- your @POST|GET|OPTIONS \/mcp@ route.
handleMcpRequest :: McpServer p -> Wai.Request -> LBS.ByteString -> IO Wai.Response
handleMcpRequest server request bodyBytes = case Wai.requestMethod request of
    "POST" -> handlePost server request bodyBytes
    "GET" -> pure $ jsonResponse HTTP.status200 $ object
        [ "name" .= server.serverName
        , "transport" .= ("streamable-http" :: Text)
        , "docs" .= ("Use POST with JSON-RPC 2.0 envelopes." :: Text)
        ]
    "OPTIONS" -> pure $ Wai.responseLBS HTTP.status204 corsHeaders ""
    _ -> pure $ jsonResponse HTTP.status405 $ object [ "error" .= ("method not allowed" :: Text) ]

handlePost :: McpServer p -> Wai.Request -> LBS.ByteString -> IO Wai.Response
handlePost server request bodyBytes =
    case eitherDecode bodyBytes of
        Left err -> pure $ rpcResponse (JsonRpcErrorResp Nothing (errorParseError (Text.pack err)))
        Right (rpc :: JsonRpcRequest) -> case rpc.method of
            -- Notifications never need auth and never expect a body.
            "notifications/initialized" -> pure $ Wai.responseLBS HTTP.status202 corsHeaders ""
            -- Everything else (including `initialize` and `ping`) requires auth.
            -- Claude.ai's connector flow only triggers the OAuth dance when an
            -- authed request — typically `initialize` on connect — gets a 401.
            _ -> do
                authed <- server.authenticate request
                case authed of
                    Nothing -> pure $ unauthorizedResponse server request rpc.reqId
                    Just p -> case rpc.method of
                        "initialize" -> pure $ rpcResponse (handleInitialize server rpc)
                        "ping" -> pure $ rpcResponse (JsonRpcResult rpc.reqId (object []))
                        _ -> do
                            result <- Exception.try (server.withScope p (dispatch server request p rpc))
                            case result of
                                Left (e :: SomeException) -> pure $ rpcResponse $
                                    JsonRpcErrorResp rpc.reqId (errorFromException e)
                                Right resp -> pure $ rpcResponse resp

dispatch :: McpServer p -> Wai.Request -> p -> JsonRpcRequest -> IO JsonRpcResponse
dispatch server request p rpc = case rpc.method of
    "tools/list" -> pure $ JsonRpcResult rpc.reqId $ object
        [ "tools" .= map toolDefinitionJson available ]
    "tools/call" ->
        case paramText "name" rpc.params of
            Nothing -> pure $ JsonRpcErrorResp rpc.reqId (errorInvalidParams "missing tool name")
            Just toolName ->
                let arguments = fromMaybe (object []) (paramValue "arguments" rpc.params)
                in case find (\t -> t.name == toolName) available of
                    Nothing -> pure $ JsonRpcResult rpc.reqId $
                        renderToolResult (ErrorResult ("unknown tool: " <> toolName))
                    Just tool -> do
                        res <- tool.handler arguments
                        pure $ JsonRpcResult rpc.reqId (renderToolResult res)
    other -> pure $ JsonRpcErrorResp rpc.reqId (errorMethodNotFound ("unknown method: " <> other))
  where
    available = server.tools request p

handleInitialize :: McpServer p -> JsonRpcRequest -> JsonRpcResponse
handleInitialize server rpc = JsonRpcResult rpc.reqId $ object
    [ "protocolVersion" .= protocolVersion
    , "capabilities" .= serverCapabilities
    , "serverInfo" .= mkServerInfo server.serverName server.serverVersion
    ]

------------------------------------------------------------
-- Auth header
------------------------------------------------------------

-- | Read @Authorization: Bearer <token>@ from the request.
extractBearer :: Wai.Request -> Maybe Text
extractBearer request =
    case lookup "Authorization" (Wai.requestHeaders request) of
        Just header ->
            let txt = TextEnc.decodeUtf8 header
            in Text.strip <$> Text.stripPrefix "Bearer " txt
        Nothing -> Nothing

------------------------------------------------------------
-- WAI helpers
------------------------------------------------------------

corsHeaders :: [HTTP.Header]
corsHeaders =
    [ ("Access-Control-Allow-Origin", "*")
    , ("Access-Control-Allow-Methods", "POST, GET, OPTIONS")
    , ("Access-Control-Allow-Headers", "Authorization, Content-Type")
    ]

-- | Always emit a real 401 + @WWW-Authenticate@ on auth failure so MCP clients
-- (Claude.ai, Claude Code) can trigger the OAuth dance or surface the error.
unauthorizedResponse :: McpServer p -> Wai.Request -> Maybe Value -> Wai.Response
unauthorizedResponse server request rid =
    let issuerUrl = server.resolveIssuer request
        metadata = issuerUrl <> "/.well-known/oauth-protected-resource"
        challenge = "Bearer realm=\"mcp\", resource_metadata=\"" <> metadata <> "\""
        body = Aeson.encode (JsonRpcErrorResp rid (errorUnauthorized "unauthorized"))
    in Wai.responseLBS HTTP.status401
        ((HTTP.hContentType, "application/json") :
         ("WWW-Authenticate", TextEnc.encodeUtf8 challenge) :
         corsHeaders)
        body

jsonResponse :: HTTP.Status -> Value -> Wai.Response
jsonResponse status v = Wai.responseLBS status
    ((HTTP.hContentType, "application/json") : corsHeaders)
    (Aeson.encode v)

rpcResponse :: JsonRpcResponse -> Wai.Response
rpcResponse resp = Wai.responseLBS HTTP.status200
    ((HTTP.hContentType, "application/json") : corsHeaders)
    (Aeson.encode resp)

------------------------------------------------------------
-- param helpers
------------------------------------------------------------

paramText :: Text -> Value -> Maybe Text
paramText k (Object o) = case KM.lookup (AesonKey.fromText k) o of
    Just (String t) -> Just t
    _ -> Nothing
paramText _ _ = Nothing

paramValue :: Text -> Value -> Maybe Value
paramValue k (Object o) = KM.lookup (AesonKey.fromText k) o
paramValue _ _ = Nothing
