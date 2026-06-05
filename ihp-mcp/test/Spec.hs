{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ImplicitParams #-}
{-# LANGUAGE NoImplicitPrelude #-}
{-# LANGUAGE BlockArguments #-}
{-# LANGUAGE ScopedTypeVariables #-}

-- | Integration tests for the OAuth token endpoint, exercising the atomic
-- auth-code / refresh-token claiming and reuse detection against a real
-- Postgres. Requires @DATABASE_URL@ pointing at a database loaded with
-- @test\/schema.sql@ (the runner / @nix flake check@ sets this up).
module Main (main) where

import IHP.Prelude
import IHP.ModelSupport (ModelContext, withModelContext, noopLogger, unsafeSqlQuery)
import System.Environment (getEnv)
import Test.Hspec
import Data.Aeson (Value (..), object, (.=), encode, decode)
import qualified Data.Aeson.Key as K
import qualified Data.Aeson.KeyMap as KM
import qualified Data.ByteString.Builder as BB
import qualified Data.ByteString.Lazy as LBS
import qualified Data.Text.Encoding as TE
import Data.IORef (newIORef, modifyIORef', readIORef)
import qualified Network.Wai as Wai
import Network.HTTP.Types (statusCode)
import Network.HTTP.Types.URI (renderSimpleQuery)
import Database.PostgreSQL.Simple (Only (..))
import Data.UUID (UUID)
import Control.Concurrent.Async (concurrently)
import Data.List (sort)

import IHP.MCP.OAuth.Endpoints (handleRegister, handleToken, mintAuthorizationCode)

-- RFC 7636 Appendix B verifier/challenge pair.
verifier, challenge :: Text
verifier  = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"

main :: IO ()
main = do
    dbUrl <- getEnv "DATABASE_URL"
    withModelContext (cs dbUrl) noopLogger \modelContext -> do
        let ?modelContext = modelContext
        hspec spec

spec :: (?modelContext :: ModelContext) => Spec
spec = describe "IHP.MCP.OAuth.Endpoints" do
    it "runs register → code → token → refresh and detects reuse" do
        clientId <- registerClient
        uid <- newUser
        code <- mintAuthorizationCode clientId uid "https://client/cb" challenge "mcp_read"

        -- exchange the code for a token pair
        r1 <- exchangeCode clientId code
        statusOf r1 `shouldBe` 200
        refresh1 <- jsonText "refresh_token" <$> bodyOf r1

        -- the same code can't be redeemed twice
        r2 <- exchangeCode clientId code
        statusOf r2 `shouldBe` 400

        -- refreshing rotates to a new pair
        r3 <- refreshWith clientId refresh1
        statusOf r3 `shouldBe` 200

        -- reusing the now-rotated refresh token is rejected
        r4 <- refreshWith clientId refresh1
        statusOf r4 `shouldBe` 400

    it "rejects a wrong PKCE verifier" do
        clientId <- registerClient
        uid <- newUser
        code <- mintAuthorizationCode clientId uid "https://client/cb" challenge "mcp_read"
        r <- handleToken (form
            [ ("grant_type", "authorization_code"), ("code", code)
            , ("code_verifier", "the-wrong-verifier")
            , ("client_id", clientId), ("redirect_uri", "https://client/cb") ])
        statusOf r `shouldBe` 400

    it "lets exactly one of two concurrent code exchanges win (atomic claim)" do
        clientId <- registerClient
        uid <- newUser
        code <- mintAuthorizationCode clientId uid "https://client/cb" challenge "mcp_read"
        (a, b) <- concurrently (exchangeCode clientId code) (exchangeCode clientId code)
        sort [statusOf a, statusOf b] `shouldBe` [200, 400]

------------------------------------------------------------
-- helpers
------------------------------------------------------------

newUser :: (?modelContext :: ModelContext) => IO UUID
newUser = do
    rows :: [Only UUID] <- unsafeSqlQuery "INSERT INTO users DEFAULT VALUES RETURNING id" ()
    case rows of
        (Only u : _) -> pure u
        _ -> error "newUser: no id returned"

registerClient :: (?modelContext :: ModelContext) => IO Text
registerClient = do
    resp <- handleRegister (encode (object
        [ "redirect_uris" .= (["https://client/cb"] :: [Text])
        , "client_name" .= ("Test client" :: Text) ]))
    jsonText "client_id" <$> bodyOf resp

exchangeCode :: (?modelContext :: ModelContext) => Text -> Text -> IO Wai.Response
exchangeCode clientId code = handleToken (form
    [ ("grant_type", "authorization_code"), ("code", code), ("code_verifier", verifier)
    , ("client_id", clientId), ("redirect_uri", "https://client/cb") ])

refreshWith :: (?modelContext :: ModelContext) => Text -> Text -> IO Wai.Response
refreshWith clientId refresh = handleToken (form
    [ ("grant_type", "refresh_token"), ("refresh_token", refresh), ("client_id", clientId) ])

form :: [(Text, Text)] -> LBS.ByteString
form kvs = LBS.fromStrict (renderSimpleQuery False [ (TE.encodeUtf8 k, TE.encodeUtf8 v) | (k, v) <- kvs ])

statusOf :: Wai.Response -> Int
statusOf = statusCode . Wai.responseStatus

bodyOf :: Wai.Response -> IO LBS.ByteString
bodyOf resp = do
    let (_, _, withBody) = Wai.responseToStream resp
    ref <- newIORef mempty
    withBody \streamingBody -> streamingBody (\b -> modifyIORef' ref (<> b)) (pure ())
    BB.toLazyByteString <$> readIORef ref

jsonText :: Text -> LBS.ByteString -> Text
jsonText key lbs = case decode lbs of
    Just (Object o) | Just (String t) <- KM.lookup (K.fromText key) o -> t
    _ -> error ("jsonText: missing field " <> cs key <> " in " <> cs lbs)
