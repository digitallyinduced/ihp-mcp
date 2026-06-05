{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE DuplicateRecordFields #-}
{-# LANGUAGE NamedFieldPuns #-}
{-# LANGUAGE OverloadedRecordDot #-}

-- | JSON-RPC 2.0 + MCP protocol envelope types.
--
-- This module is framework-agnostic: it depends only on @aeson@ and @text@.
-- It carries no transport, no auth and no IHP coupling — those live in
-- "MCP.Protocol.Server" (transport) and the @ihp-mcp@ package (storage).
module MCP.Protocol.Types
    ( -- * JSON-RPC envelopes
      JsonRpcRequest (..)
    , JsonRpcResponse (..)
    , McpError (..)
      -- * Error constructors (JSON-RPC 2.0 codes + MCP @-32001@ unauthorized)
    , errorParseError
    , errorInvalidRequest
    , errorMethodNotFound
    , errorInvalidParams
    , errorInternal
    , errorUnauthorized
    , errorFromException
      -- * MCP handshake values
    , protocolVersion
    , mkServerInfo
    , serverCapabilities
    ) where

import Prelude
import Control.Exception (SomeException)
import Data.Aeson
import Data.Maybe (catMaybes)
import Data.Text (Text)
import qualified Data.Text as Text

-- | The MCP protocol version this server speaks. Clients negotiate via
-- @initialize@. @2025-03-26@ is the first MCP revision that includes
-- OAuth-based authorization; Claude.ai will not trigger the OAuth dance
-- against an older-version server.
protocolVersion :: Text
protocolVersion = "2025-03-26"

-- | Build the @serverInfo@ object advertised in the @initialize@ result.
mkServerInfo :: Text -> Text -> Value
mkServerInfo name version = object
    [ "name" .= name
    , "version" .= version
    ]

-- | Tools-only capabilities. No resources, prompts or sampling (yet — this is
-- the single place to extend when the library grows beyond tools).
serverCapabilities :: Value
serverCapabilities = object
    [ "tools" .= object [ "listChanged" .= False ]
    ]

data JsonRpcRequest = JsonRpcRequest
    { jsonrpc :: !Text
    , method :: !Text
    , params :: !Value
    , reqId :: !(Maybe Value)
    } deriving (Show)

instance FromJSON JsonRpcRequest where
    parseJSON = withObject "JsonRpcRequest" $ \v -> do
        jsonrpc <- v .:? "jsonrpc" .!= "2.0"
        method <- v .: "method"
        params <- v .:? "params" .!= Null
        reqId <- v .:? "id"
        pure JsonRpcRequest { jsonrpc, method, params, reqId }

data JsonRpcResponse
    = JsonRpcResult { reqId :: !(Maybe Value), result :: !Value }
    | JsonRpcErrorResp { reqId :: !(Maybe Value), errBody :: !McpError }
    deriving (Show)

instance ToJSON JsonRpcResponse where
    toJSON (JsonRpcResult mid r) = object
        [ "jsonrpc" .= ("2.0" :: Text)
        , "id" .= mid
        , "result" .= r
        ]
    toJSON (JsonRpcErrorResp mid e) = object
        [ "jsonrpc" .= ("2.0" :: Text)
        , "id" .= mid
        , "error" .= e
        ]

data McpError = McpError
    { code :: !Int
    , message :: !Text
    , errData :: !(Maybe Value)
    } deriving (Show)

instance ToJSON McpError where
    toJSON McpError { code, message, errData } =
        object $ catMaybes
            [ Just ("code" .= code)
            , Just ("message" .= message)
            , (\d -> "data" .= d) <$> errData
            ]

errorParseError, errorInvalidRequest, errorMethodNotFound, errorInvalidParams, errorInternal, errorUnauthorized :: Text -> McpError
errorParseError msg = McpError { code = -32700, message = msg, errData = Nothing }
errorInvalidRequest msg = McpError { code = -32600, message = msg, errData = Nothing }
errorMethodNotFound msg = McpError { code = -32601, message = msg, errData = Nothing }
errorInvalidParams msg = McpError { code = -32602, message = msg, errData = Nothing }
errorInternal msg = McpError { code = -32603, message = msg, errData = Nothing }
errorUnauthorized msg = McpError { code = -32001, message = msg, errData = Nothing }

-- | Wrap an arbitrary exception as an internal MCP error, surfacing the
-- @show@n message in the @data@ field for debugging.
errorFromException :: SomeException -> McpError
errorFromException e = McpError
    { code = -32603
    , message = "internal error"
    , errData = Just (toJSON (Text.pack (show e)))
    }
