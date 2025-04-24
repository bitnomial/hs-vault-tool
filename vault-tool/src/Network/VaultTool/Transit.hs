{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE DerivingStrategies #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE OverloadedStrings #-}

{- | Implements a subset of the Vault Transit secrets engine API.
c.f. https://developer.hashicorp.com/vault/api-docs/secret/transit#encrypt-data

The Transit secrets engine does not store secrets. Instead, it provides encryption
and decryption of data the client intends to persist themselves. The client persists
encrypted data and only decrypts it at the point where it's needed. This reduces
the risk and loss associated with a data breach.
-}
module Network.VaultTool.Transit (
    KeyName,
    Base64 (..),
    CipherText (..),
    encodeBase64,
    decodeBase64,
    encryptBase64,
    decryptBase64,
    encryptByteString,
    decryptByteString,
    encryptText,
    decryptText,
) where

import Control.Exception (throwIO)
import Control.Monad ((<=<))
import qualified Data.Aeson as A
import Data.ByteString (ByteString)
import qualified Data.ByteString as B
import qualified Data.ByteString.Base64 as B64
import qualified Data.ByteString.Char8 as C8
import Data.Text (Text)
import qualified Data.Text as T
import Data.Text.Encoding (decodeLatin1, encodeUtf8)
import GHC.Generics (Generic)

import Network.VaultTool.Internal (
    newPostRequest,
    runVaultRequestAuthenticated,
 )
import Network.VaultTool.Types (
    Authenticated,
    VaultConnection,
    VaultMountedPath (VaultMountedPath),
 )

type KeyName = Text

newtype Base64 = Base64 {getBase64 :: ByteString}
    deriving (Eq, Ord, Read, Show, Generic)

instance A.ToJSON Base64 where
    toJSON = A.toJSON . C8.unpack . getBase64
    toEncoding = A.toEncoding . C8.unpack . getBase64

instance A.FromJSON Base64 where
    parseJSON = fmap (Base64 . C8.pack) . A.parseJSON

newtype CipherText = CipherText {getCipherText :: Base64}
    deriving (Eq, Ord, Read, Show, Generic)
    deriving newtype (A.FromJSON)

instance A.ToJSON CipherText where
    -- Note that we only support a v1 key for encryption and decryption
    toJSON (CipherText contents) = A.toJSON $ "vault:v1:" <> C8.unpack (getBase64 contents)

encodeBase64 :: ByteString -> Base64
encodeBase64 = Base64 . B64.encode

decodeBase64 :: Base64 -> Either String ByteString
decodeBase64 = B64.decode . getBase64

encryptBase64 :: VaultConnection Authenticated -> VaultMountedPath -> KeyName -> Base64 -> IO CipherText
encryptBase64 conn path key =
    maybe
        (throwIO . userError $ "Unexpected response from vault transit encrypt")
        (pure . getCyphertext)
        <=< runVaultRequestAuthenticated conn
            . newPostRequest (mkUri path key)
            . mkBody
  where
    mkUri (VaultMountedPath p) k = T.intercalate "/" [p, "encrypt", k]

    mkBody = Just . A.object . pure . ("plaintext" A..=)

decryptBase64 :: VaultConnection Authenticated -> VaultMountedPath -> KeyName -> CipherText -> IO Base64
decryptBase64 conn path key =
    maybe
        (throwIO . userError $ "Unexpected response from vault transit decrypt")
        (pure . getPlaintext)
        <=< runVaultRequestAuthenticated conn
            . newPostRequest (mkUri path key)
            . mkBody
  where
    mkUri (VaultMountedPath p) k = T.intercalate "/" [p, "decrypt", k]

    mkBody = Just . A.object . pure . ("ciphertext" A..=)

encryptByteString :: VaultConnection Authenticated -> VaultMountedPath -> KeyName -> ByteString -> IO CipherText
encryptByteString conn path key = encryptBase64 conn path key . encodeBase64

decryptByteString :: VaultConnection Authenticated -> VaultMountedPath -> KeyName -> CipherText -> IO ByteString
decryptByteString conn path key =
    either decodeError pure . decodeBase64 <=< decryptBase64 conn path key
  where
    decodeError msg =
        throwIO . userError $
            "Failed to decode Base64 response value from vault transit decrypt: " <> msg

encryptText :: VaultConnection Authenticated -> VaultMountedPath -> KeyName -> Text -> IO CipherText
encryptText conn path key = encryptByteString conn path key . encodeUtf8

decryptText :: VaultConnection Authenticated -> VaultMountedPath -> KeyName -> CipherText -> IO Text
decryptText conn path key = fmap decodeLatin1 . decryptByteString conn path key

newtype VaultCiphertext
    = VaultCiphertext {getCyphertext :: CipherText}

instance A.FromJSON VaultCiphertext where
    parseJSON = A.withObject "VaultCiphertext" $ \obj -> do
        data' <- obj A..: "data"
        Base64 ciphertext <- data' A..: "ciphertext"
        case B.split colon ciphertext of
            -- Typically, the ciphertext will look like
            --    "vault:v1:<ciphertext>"
            --
            -- Note that we only support a v1 key for encryption and decryption
            ["vault", "v1", cphtxt] -> pure $ VaultCiphertext (CipherText $ Base64 cphtxt)
            _otherwise -> fail "Undecipherable ciphertext"
      where
        colon = fromIntegral $ fromEnum ':'

newtype VaultPlaintext a
    = VaultPlaintext {getPlaintext :: a}

instance (A.FromJSON a) => A.FromJSON (VaultPlaintext a) where
    parseJSON = A.withObject "VaultPlaintext" $ \obj -> do
        data' <- obj A..: "data"
        VaultPlaintext <$> data' A..: "plaintext"