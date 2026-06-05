{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE OverloadedRecordDot #-}

module Main (main) where

import Test.Hspec
import Data.Aeson
import Data.Text (Text)
import qualified Data.Text as Text

import MCP.OAuth
import MCP.Protocol.Types
import MCP.Protocol.Tool

main :: IO ()
main = hspec $ do
    describe "PKCE S256 (RFC 7636 Appendix B vector)" $ do
        let verifier  = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
            challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
        it "accepts the matching challenge" $
            verifyPkceS256 verifier challenge `shouldBe` True
        it "rejects a wrong challenge" $
            verifyPkceS256 verifier "not-the-challenge" `shouldBe` False
        it "rejects an empty challenge (length mismatch)" $
            verifyPkceS256 verifier "" `shouldBe` False

    describe "token minting & hashing" $ do
        it "hashToken is deterministic" $
            hashToken "abc" `shouldBe` hashToken "abc"
        it "distinct tokens hash distinctly" $
            (hashToken "abc" == hashToken "abd") `shouldBe` False
        it "generateClientId carries the mcp_client_ prefix" $ do
            cid <- generateClientId
            ("mcp_client_" `Text.isPrefixOf` cid) `shouldBe` True
        it "generateAccessToken returns mcp_oauth_ plaintext whose hash matches hashToken" $ do
            (plain, hash) <- generateAccessToken
            ("mcp_oauth_" `Text.isPrefixOf` plain) `shouldBe` True
            hash `shouldBe` hashToken plain
        it "two secrets differ (CSPRNG)" $ do
            a <- generateSecret
            b <- generateSecret
            (a == b) `shouldBe` False

    describe "JSON-RPC envelopes" $ do
        it "parses a request, defaulting jsonrpc and params" $
            case decode "{\"method\":\"tools/list\",\"id\":1}" of
                Just (req :: JsonRpcRequest) -> do
                    req.method  `shouldBe` "tools/list"
                    req.jsonrpc `shouldBe` "2.0"
                    req.params  `shouldBe` Null
                    req.reqId   `shouldBe` Just (Number 1)
                Nothing -> expectationFailure "request failed to parse"
        it "encodes a result envelope" $
            toJSON (JsonRpcResult (Just (Number 1)) (object ["ok" .= True]))
                `shouldBe` object
                    [ "jsonrpc" .= ("2.0" :: Text)
                    , "id" .= Number 1
                    , "result" .= object ["ok" .= True]
                    ]
        it "encodes an error envelope and omits absent data" $
            toJSON (JsonRpcErrorResp (Just (Number 2)) (errorMethodNotFound "nope"))
                `shouldBe` object
                    [ "jsonrpc" .= ("2.0" :: Text)
                    , "id" .= Number 2
                    , "error" .= object [ "code" .= (-32601 :: Int), "message" .= ("nope" :: Text) ]
                    ]

    describe "Tool" $ do
        let def = object
                [ "name" .= ("run_sql" :: Text)
                , "description" .= ("desc" :: Text)
                , "inputSchema" .= object ["type" .= ("object" :: Text)]
                ]
        it "toolFromJson round-trips the definition object" $ do
            let t = toolFromJson def (\_ -> pure (TextResult "x"))
            t.name `shouldBe` "run_sql"
            t.description `shouldBe` "desc"
            toolDefinitionJson t `shouldBe` def
        it "renders TextResult as a non-error text block" $
            renderToolResult (TextResult "hi") `shouldBe` object
                [ "content" .= [object ["type" .= ("text" :: Text), "text" .= ("hi" :: Text)]]
                , "isError" .= False
                ]
        it "renders ErrorResult with isError=true" $
            renderToolResult (ErrorResult "bad") `shouldBe` object
                [ "content" .= [object ["type" .= ("text" :: Text), "text" .= ("bad" :: Text)]]
                , "isError" .= True
                ]
        it "passes RawResult through verbatim" $
            renderToolResult (RawResult (object ["custom" .= True]))
                `shouldBe` object ["custom" .= True]
