{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE OverloadedStrings #-}

{- | A library for working with Vault's TOTP secrets engine
   https://www.vaultproject.io/api-docs/secret/totp

 Unless otherwise specified, all IO functions in this module may
 potentially throw 'HttpException' or 'VaultException'
-}
module Network.VaultTool.TOTP (
    GenerateKeyRequest (..),
    HashAlgorithm (..),
    DigitCount (..),
    Skew (..),
    GeneratedKey (..),
    mkGenerateKeyRequest,
    generateKey,

    Key (..),
    getKey,

    listKeys,

    deleteKey,

    Code (..),
    generateCode,

    CodeStatus (..),
    validateCode,
) where

import Data.Aeson (
    FromJSON (..),
    ToJSON (..),
    Value (..),
    (.:),
    withObject,
 )
import Data.Aeson.Utils (DataWrapper (..), (.=!), (.=?), object)
import Data.Bool (bool)
import Data.Maybe (catMaybes)
import Data.Text (Text)
import qualified Data.Text as T
import Web.HttpApiData (FromHttpApiData (..), ToHttpApiData (..))

import Network.VaultTool.Internal (
    newDeleteRequest,
    newGetRequest,
    newListRequest,
    newPostRequest,
    runVaultRequestAuthenticated,
    runVaultRequestAuthenticated_,
    withStatusCodes,
 )
import Network.VaultTool.Types (
    Authenticated,
    VaultConnection,
    VaultMountedPath (..),
 )

-- | The name associated with a TOTP key
type KeyName = Text

-- | The issuer associated with a TOTP key
type Issuer = Text

-- | The acconut name associated with a TOTP key
type AccountName = Text

-- | The data needed for vault to generate a TOTP Key
-- <https://www.vaultproject.io/api-docs/secret/totp#parameters>
data GenerateKeyRequest = GenerateKeyRequest
    { -- | The name of the key to create
      gkrKeyName :: Text,
      -- | The name of the key's issuing organization
      gkrIssuer :: Text,
      -- | The name of the account associated with the key
      gkrAccountName :: Text,
      -- | The size of the key in bytes (defaults: 20)
      gkrKeySize :: Maybe Int,
      -- | The length of time in seconds used to generate a counter for the TOTP code calculation (default: 30)
      gkrPeriod :: Maybe Int,
      -- | The hashing algorithm to use. Options are 'SHA1', 'SHA256', 'SHA512'. (default: 'SHA1')
      gkrAlgorithm :: Maybe HashAlgorithm,
      -- | The number of digits in the generated TOTP code. Options are 'SixDigits' or 'EightDigits'. (default: 'SixDigits')
      gkrDigitCount :: Maybe DigitCount,
      -- | The number of delay periods allowed when validating TOTP code. Options are 'NoSkew' or 'OnePeriodSkew'.
      -- (default: 'OnePeriodSkew')
      gkrSkew :: Maybe Skew,
      -- | The pixel size of the square QR code when generating a new key (default: 200)
      gkrQrSize :: Maybe Int
    }
    deriving (Show, Eq)

instance ToJSON GenerateKeyRequest where
    toJSON x = object
        [ "generate" .=! True
        , "issuer" .=! gkrIssuer x
        , "account_name" .=! gkrAccountName x
        , "key_size" .=? gkrKeySize x
        , "period" .=? gkrPeriod x
        , "algorithm" .=? gkrAlgorithm x
        , "digits" .=? gkrDigitCount x
        , "skew" .=? gkrSkew x
        , "qr_size" .=? gkrQrSize x
        ]

data HashAlgorithm = SHA1 | SHA256 | SHA512
    deriving (Show, Eq)

instance FromJSON HashAlgorithm where
    parseJSON (String "SHA1") = pure SHA1
    parseJSON (String "SHA256") = pure SHA256
    parseJSON (String "SHA512") = pure SHA512
    parseJSON x = fail $ "Expected 'SHA1', 'SHA256' or 'SHA512' but received " <> show x

instance ToJSON HashAlgorithm where
    toJSON = \case
        SHA1 -> String "SHA1"
        SHA256 -> String "SHA256"
        SHA512 -> String "SHA512"

data DigitCount = SixDigits | EightDigits
    deriving (Show, Eq)

instance FromJSON DigitCount where
    parseJSON (Number 6) = pure SixDigits
    parseJSON (Number 8) = pure EightDigits
    parseJSON x = fail $ "Expected 6 or 8 but received " <> show x

instance ToJSON DigitCount where
    toJSON = \case
        SixDigits -> Number 6
        EightDigits -> Number 8

data Skew = NoSkew | OnePeriodSkew
    deriving (Show, Eq)

instance ToJSON Skew where
    toJSON = \case
        NoSkew -> Number 0
        OnePeriodSkew -> Number 1

-- | The newly generated Vault TOTP key which includes a
-- [TOTP Key URI](https://github.com/google/google-authenticator/wiki/Key-Uri-Format)
-- and a base64 encoded QR code representation of the TOTP Key URI. The QR code can be embedded in a webpage using an
-- img tag with the prefix:
--
-- > data:image/png;base64
--
-- For example, if gkrBarcode = ABC:
--
-- > <img src="data:image/png;base64,ABC" />
data GeneratedKey = GeneratedKey
    { -- | The resulting base64 encoded QR code PNG
      gkrBarcode :: Text,
      -- | The resulting [TOTP Key URI](https://github.com/google/google-authenticator/wiki/Key-Uri-Format)
      gkrUrl :: Text
    }
    deriving (Show, Eq)

instance FromJSON GeneratedKey where
    parseJSON = withObject "GeneratedKey" $ \v ->
        GeneratedKey <$> v .: "barcode" <*> v .: "url"

-- | Constructs a 'GenerateKeyRequest' with the given required fields and defaults all the optional (Maybe) fields to Nothing
mkGenerateKeyRequest :: KeyName -> Issuer -> AccountName -> GenerateKeyRequest
mkGenerateKeyRequest keyName issuer accountName = GenerateKeyRequest
    { gkrKeyName = keyName
    , gkrIssuer = issuer
    , gkrAccountName = accountName
    , gkrKeySize = Nothing
    , gkrPeriod = Nothing
    , gkrAlgorithm = Nothing
    , gkrDigitCount = Nothing
    , gkrSkew = Nothing
    , gkrQrSize = Nothing
    }

-- | Generates a new TOTP code via Vault's TOTP API
generateKey :: VaultConnection Authenticated -- ^ An authenticated connection to talk to Vault
            -> VaultMountedPath -- ^ The TOTP mount path
            -> GenerateKeyRequest -- ^ The TOTP key to create
            -> IO GeneratedKey -- ^ The resulting TOTP key
generateKey conn path req = fmap unDataWrapper
    . runVaultRequestAuthenticated conn
    . newPostRequest (mkPathWithKey KeysNamespace path $ gkrKeyName req)
    $ Just req

-- | A TOTP key managed in Vault
data Key = Key
    {
      -- | The name of the account associated with the key
      kAccountName :: Text,
      -- | The hashing algorithm to use. Options are 'SHA1', 'SHA256', 'SHA512'. (default: 'SHA1')
      kAlgorithm :: HashAlgorithm,
      -- | The number of digits in the generated TOTP code. Options are 'SixDigits' or 'EightDigits'. (default: 'SixDigits')
      kDigitCount :: DigitCount,
      -- | The name of the key's issuing organization
      kIssuer :: Text,
      -- | The length of time in seconds used to generate a counter for the TOTP code calculation (default: 30)
      kPeriod :: Int
    }
    deriving (Show, Eq)

instance FromJSON Key where
    parseJSON = withObject "Key" $ \v -> Key
        <$> v .: "account_name"
        <*> v .: "algorithm"
        <*> v .: "digits"
        <*> v .: "issuer"
        <*> v .: "period"

-- | Returns the key associated with the given key name
getKey :: VaultConnection Authenticated -- ^ An authenticated connection to talk to Vault
       -> VaultMountedPath -- ^ The TOTP mount path
       -> KeyName -- ^ The name of the TOTP key to retrieve
       -> IO Key -- ^ The key corresponding to the given 'KeyName'
getKey conn path = fmap unDataWrapper
    . runVaultRequestAuthenticated conn
    . newGetRequest
    . mkPathWithKey KeysNamespace path

-- | Represents a list of key names
newtype KeyNames = KeyNames {unKeyNames :: [KeyName]}
    deriving (Show, Eq)

instance FromJSON KeyNames where
    parseJSON = withObject "KeyNames" $ fmap KeyNames . (.: "keys")

-- | Returns a list of TOTP keys stored in the given mount path
listKeys :: VaultConnection Authenticated -- ^ An authenticated connection to talk to Vault
         -> VaultMountedPath -- ^ The TOTP mount path
         -> IO [KeyName] -- ^ The list of TOTP key names found in the given mount path
listKeys conn = fmap (unKeyNames . unDataWrapper)
    . runVaultRequestAuthenticated conn
    . newListRequest
    . mkPathWithoutKey KeysNamespace

-- | Deletes the key associated with the given key name
deleteKey :: VaultConnection Authenticated -- ^ An authenticated connection to talk to Vault
          -> VaultMountedPath -- ^ The TOTP mount path
          -> KeyName -- ^ The name of the TOTP key to delete
          -> IO ()
deleteKey conn path = runVaultRequestAuthenticated_ conn
    . withStatusCodes [200, 204]
    . newDeleteRequest
    . mkPathWithKey KeysNamespace path

-- | A six or eight digit TOTP code
newtype Code = Code {unCode :: Text}
    deriving (Show, Eq, FromHttpApiData, ToHttpApiData)

instance FromJSON Code where
    parseJSON = withObject "Code" $ fmap Code . (.: "code")

instance ToJSON Code where
    toJSON x = object ["code" .=! unCode x]

-- | Generates a TOTP 'Code' for the given key
generateCode :: VaultConnection Authenticated -- ^ An authenticated connection to talk to Vault
             -> VaultMountedPath -- ^ The TOTP mount path
             -> KeyName -- ^ The name of the TOTP key that will be used to generate a code
             -> IO Code -- ^ The resulting code
generateCode conn path = fmap unDataWrapper
    . runVaultRequestAuthenticated conn
    . newGetRequest
    . mkPathWithKey CodeNamespace path

-- | Validating a code results in a code status which specifies the code is either valid or invalid
data CodeStatus = InvalidCode | ValidCode
    deriving (Show, Eq)

instance FromJSON CodeStatus where
    parseJSON = withObject "Valid" $ fmap (bool InvalidCode ValidCode) . (.: "valid")

-- | Validate the TOTP 'Code' generated for the given key
validateCode :: VaultConnection Authenticated -- ^ An authenticated connection to talk to Vault
             -> VaultMountedPath -- ^ The TOTP mount path
             -> KeyName -- ^ The name of the TOTP key used to validate the given code
             -> Code -- ^ The code to validate
             -> IO CodeStatus -- ^ The resulting validation status
validateCode conn path keyName = fmap unDataWrapper
    . runVaultRequestAuthenticated conn
    . newPostRequest (mkPathWithKey CodeNamespace path keyName)
    . Just

data EndpointNamespace = KeysNamespace | CodeNamespace

mkPathWithKey :: EndpointNamespace -> VaultMountedPath -> Text -> Text
mkPathWithKey namespace path = vaultEndpointPath namespace path . Just

mkPathWithoutKey :: EndpointNamespace -> VaultMountedPath -> Text
mkPathWithoutKey namespace path = vaultEndpointPath namespace path Nothing

vaultEndpointPath :: EndpointNamespace -> VaultMountedPath -> Maybe KeyName -> Text
vaultEndpointPath namespace (VaultMountedPath mountedPath) keyName = T.intercalate "/"
    $ catMaybes [Just mountedPath, Just (toText namespace), keyName]
  where
    toText = \case
        KeysNamespace -> "keys"
        CodeNamespace -> "code"
