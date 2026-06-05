{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE OverloadedRecordDot #-}

-- | The tool abstraction.
--
-- This replaces the hand-rolled @toolDefinitions :: [Value]@ list plus a
-- parallel @runTool@ @case@ statement that both consuming apps duplicated.
-- A 'Tool' co-locates its JSON Schema and its handler, so the @tools/list@
-- advertisement and the @tools/call@ dispatch can never drift apart.
module MCP.Protocol.Tool
    ( Tool (..)
    , ToolResult (..)
    , toolDefinitionJson
    , toolFromJson
    , renderToolResult
    ) where

import Prelude
import Data.Aeson
import qualified Data.Aeson.Key as AesonKey
import qualified Data.Aeson.KeyMap as KM
import Data.Maybe (fromMaybe)
import Data.Text (Text)

-- | The outcome of running a tool.
data ToolResult
    = TextResult !Text
      -- ^ A plain-text body. Wrapped as
      -- @{ content: [{ type: "text", text }], isError: false }@.
    | ErrorResult !Text
      -- ^ A tool-level error (bad arguments, not-found, …). Same envelope
      -- with @isError: true@. This is distinct from a JSON-RPC protocol
      -- error: the call succeeded, the tool reported a problem.
    | RawResult !Value
      -- ^ A pre-built MCP @result@ object, spliced in verbatim. Use this for
      -- structured content the standard envelope can't express — e.g. an
      -- image content block from a document-viewing tool.

-- | A single MCP tool: its advertised schema plus the handler that runs it.
--
-- The handler is @IO@ and closes over whatever app context it needs
-- (database handle, authenticated user, request). The core never sees that
-- context — it only calls @handler arguments@.
data Tool = Tool
    { name :: !Text
    , description :: !Text
    , inputSchema :: !Value
    , handler :: Value -> IO ToolResult
    }

-- | The @{ name, description, inputSchema }@ object advertised in @tools/list@.
toolDefinitionJson :: Tool -> Value
toolDefinitionJson t = object
    [ "name" .= t.name
    , "description" .= t.description
    , "inputSchema" .= t.inputSchema
    ]

-- | Build a 'Tool' from an existing tool-definition object
-- (@{ name, description, inputSchema }@) plus a handler. Convenient when the
-- definition already exists as a 'Value' — e.g. migrating code that kept tool
-- schemas as Aeson literals. Missing/invalid fields default to empty.
toolFromJson :: Value -> (Value -> IO ToolResult) -> Tool
toolFromJson def h = Tool
    { name = textField "name"
    , description = textField "description"
    , inputSchema = fromMaybe (object []) (objField "inputSchema")
    , handler = h
    }
  where
    objField k = case def of
        Object o -> KM.lookup (AesonKey.fromText k) o
        _ -> Nothing
    textField k = case objField k of
        Just (String t) -> t
        _ -> ""

-- | Render a 'ToolResult' into the MCP @tools/call@ result object.
renderToolResult :: ToolResult -> Value
renderToolResult (RawResult v) = v
renderToolResult (TextResult txt) = object
    [ "content" .= ([textBlock txt] :: [Value])
    , "isError" .= False
    ]
renderToolResult (ErrorResult err) = object
    [ "content" .= ([textBlock err] :: [Value])
    , "isError" .= True
    ]

textBlock :: Text -> Value
textBlock t = object
    [ "type" .= ("text" :: Text)
    , "text" .= t
    ]
