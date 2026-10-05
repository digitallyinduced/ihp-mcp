{-# LANGUAGE OverloadedStrings #-}

module AppMetadataSpec (spec) where

import Data.Aeson
import qualified Data.Aeson.KeyMap as KM
import qualified Data.ByteString.Builder as Builder
import Data.IORef
import Data.Text (Text)
import qualified Network.HTTP.Types as HTTP
import qualified Network.Wai as Wai
import Test.Hspec

import MCP.Protocol.Server
import MCP.Protocol.Tool

spec :: Spec
spec = do
    describe "tool application metadata" $ do
        let definition = object
                [ "name" .= ("open_editor" :: Text)
                , "description" .= ("Open an editor" :: Text)
                , "inputSchema" .= object []
                ]
            metadata = object ["ui" .= object ["resourceUri" .= ("ui://editor" :: Text)]]
            annotations = object ["readOnlyHint" .= False, "destructiveHint" .= False]
            handler _ = pure (TextResult "Opened")
        it "preserves metadata and annotations independently" $
            mapM_ (\extensions -> do
                let extended = addFields definition extensions
                toolDefinitionJson (toolFromJson extended handler) `shouldBe` extended)
                [["_meta" .= metadata], ["annotations" .= annotations],
                 ["_meta" .= metadata, "annotations" .= annotations]]
        it "ignores non-object extension fields" $
            toolDefinitionJson (toolFromJson
                (addFields definition ["_meta" .= Null, "annotations" .= True]) handler)
                `shouldBe` definition
        it "keeps ordinary constructors and record updates usable" $ do
            let ordinary = Tool "open_editor" "Open an editor" (object []) handler
            toolDefinitionJson ordinary `shouldBe` definition
            toolDefinitionJson (ordinary { description = "Updated" })
                `shouldBe` addFields definition ["description" .= ("Updated" :: Text)]
        it "keeps client metadata out of public result fields" $ do
            let structured = object ["documentCount" .= (2 :: Int)]
                privateMetadata = object ["session" .= ("private-test-value" :: Text)]
            renderToolResult (AppResult "Opened" structured privateMetadata)
                `shouldBe` object
                    [ "content" .= [object ["type" .= ("text" :: Text), "text" .= ("Opened" :: Text)]]
                    , "structuredContent" .= structured
                    , "_meta" .= privateMetadata
                    , "isError" .= False
                    ]
    describe "authenticated text resources" $ do
        it "advertises resources and instructions on initialization" $ do
            (_, response) <- invoke resourceServer "initialize" (object [])
            field "instructions" (field "result" response) `shouldBe` String "Use the editor."
            field "resources" (field "capabilities" (field "result" response))
                `shouldBe` object ["subscribe" .= False, "listChanged" .= False]
        it "preserves default capabilities and omits absent instructions" $ do
            (_, response) <- invoke emptyServer "initialize" (object [])
            field "capabilities" (field "result" response)
                `shouldBe` object ["tools" .= object ["listChanged" .= False]]
            field "instructions" (field "result" response) `shouldBe` Null
        it "lists descriptors without resource text" $ do
            (_, response) <- invoke resourceServer "resources/list" (object [])
            field "result" response `shouldBe` object ["resources" .= [descriptor]]
        it "reads text, MIME type, and metadata" $ do
            (_, response) <- invoke resourceServer "resources/read" (object ["uri" .= ("ui://editor" :: Text)])
            field "result" response `shouldBe` object ["contents" .= [object
                [ "uri" .= ("ui://editor" :: Text), "text" .= ("<main>Editor</main>" :: Text)
                , "mimeType" .= ("text/html" :: Text), "_meta" .= resourceMetadataValue ]]]
        it "omits optional fields when absent" $ do
            let server = resourceServer { resources = \_ _ ->
                    [Resource "text://help" "Help" Nothing Nothing "Help text" Nothing] }
            (_, listed) <- invoke server "resources/list" (object [])
            field "result" listed `shouldBe` object ["resources" .=
                [object ["uri" .= ("text://help" :: Text), "name" .= ("Help" :: Text)]]]
            (_, readResult) <- invoke server "resources/read" (object ["uri" .= ("text://help" :: Text)])
            field "result" readResult `shouldBe` object ["contents" .=
                [object ["uri" .= ("text://help" :: Text), "text" .= ("Help text" :: Text)]]]
        it "returns an empty resource-template list" $ do
            (_, response) <- invoke resourceServer "resources/templates/list" (object [])
            field "result" response `shouldBe` object ["resourceTemplates" .= ([] :: [Value])]
        it "rejects missing and non-text resource URIs" $
            mapM_ (\params -> do
                (_, response) <- invoke resourceServer "resources/read" params
                field "code" (field "error" response) `shouldBe` Number (-32602))
                [object [], object ["uri" .= True]]
        it "returns resource-not-found for unknown or unauthorized URIs" $
            mapM_ (\server -> do
                (_, response) <- invoke server "resources/read" (object ["uri" .= ("ui://other" :: Text)])
                field "code" (field "error" response) `shouldBe` Number (-32002))
                [resourceServer, emptyServer]
        it "does not expose another principal's resources" $ do
            let server = resourceServer { authenticate = \_ -> pure (Just False) }
            (_, listed) <- invoke server "resources/list" (object [])
            field "result" listed `shouldBe` object ["resources" .= ([] :: [Value])]
            (_, denied) <- invoke server "resources/read" (object ["uri" .= ("ui://editor" :: Text)])
            field "code" (field "error" denied) `shouldBe` Number (-32002)
        it "requires authentication for every resource method" $
            mapM_ (\method -> do
                (status, _) <- invoke (resourceServer { authenticate = \_ -> pure Nothing }) method (object [])
                status `shouldBe` HTTP.status401)
                ["resources/list", "resources/read", "resources/templates/list"]
        it "runs resource dispatch inside the supplied scope" $ do
            scoped <- newIORef False
            let server = resourceServer { withScope = \_ action -> writeIORef scoped True >> action }
            _ <- invoke server "resources/read" (object ["uri" .= ("ui://editor" :: Text)])
            readIORef scoped `shouldReturn` True

resourceMetadataValue :: Value
resourceMetadataValue = object ["ui" .= object ["prefersBorder" .= True]]

descriptor :: Value
descriptor = object
    [ "uri" .= ("ui://editor" :: Text), "name" .= ("Editor" :: Text)
    , "description" .= ("Interactive editor" :: Text)
    , "mimeType" .= ("text/html" :: Text), "_meta" .= resourceMetadataValue
    ]

emptyServer :: McpServer Bool
emptyServer = defaultMcpServer { authenticate = \_ -> pure (Just True) }

resourceServer :: McpServer Bool
resourceServer = emptyServer
    { resources = \_ permitted -> if permitted
        then [Resource "ui://editor" "Editor" (Just "Interactive editor")
            (Just "text/html") "<main>Editor</main>" (Just resourceMetadataValue)]
        else []
    , serverInstructions = Just "Use the editor."
    }

invoke :: McpServer p -> Text -> Value -> IO (HTTP.Status, Value)
invoke server method params = do
    response <- handleMcpRequest server (Wai.defaultRequest { Wai.requestMethod = "POST" })
        (encode (object ["jsonrpc" .= ("2.0" :: Text), "id" .= (1 :: Int), "method" .= method, "params" .= params]))
    let (status, _, withBody) = Wai.responseToStream response
    bytes <- newIORef mempty
    withBody $ \stream -> stream (\chunk -> modifyIORef' bytes (<> chunk)) (pure ())
    body <- Builder.toLazyByteString <$> readIORef bytes
    case eitherDecode body of
        Left message -> expectationFailure message >> pure (status, Null)
        Right value -> pure (status, value)

-- Generic protocol-envelope assertions deliberately inspect JSON fields rather
-- than introducing application payload types into transport regression tests.
field :: Key -> Value -> Value
field key (Object values) = maybe Null id (KM.lookup key values)
field _ _ = Null

addFields :: Value -> [(Key, Value)] -> Value
addFields (Object values) fields = Object (KM.union (KM.fromList fields) values)
addFields value _ = value
