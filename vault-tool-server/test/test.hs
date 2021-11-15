{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}

module Main where

import Control.Exception (catch)
import Data.Aeson (FromJSON, ToJSON, (.=), object)
import Data.Functor (($>))
import Data.List (sort)
import Data.List.Split (splitOn)
import Data.Maybe (mapMaybe)
import Data.Text (Text)
import qualified Data.Text as T
import GHC.Generics (Generic)
import Network.HTTP.Client (Manager)
import Network.URI (URI (..), parseURI)
import System.Environment (lookupEnv)
import System.IO.Temp (withSystemTempDirectory)
import Test.Tasty.HUnit ((@?=), assertBool, assertFailure)

import Network.VaultTool (
    Authenticated,
    VaultAddress,
    VaultAppRoleParameters (..),
    VaultAppRoleSecretIdGenerateResponse (..),
    VaultConnection,
    VaultException,
    VaultHealth (..),
    VaultMount (..),
    VaultMountConfig (..),
    VaultMountOptions (..),
    VaultMountedPath (..),
    VaultSealStatus (..),
    VaultSearchPath (..),
    VaultSecretPath (..),
    VaultUnseal (..),
    authenticatedVaultConnection,
    connectToVaultAppRole,
    defaultManager,
    defaultVaultAppRoleParameters,
    unauthenticatedVaultConnection,
    vaultAppRoleCreate,
    vaultAppRoleRoleIdRead,
    vaultAppRoleSecretIdGenerate,
    vaultAuthEnable,
    vaultHealth,
    vaultInit,
    vaultMountSetTune,
    vaultMountTune,
    vaultMounts,
    vaultNewMount,
    vaultPolicyCreate,
    vaultSeal,
    vaultSealStatus,
    vaultUnmount,
    vaultUnseal,
 )
import qualified Network.VaultTool.KeyValueV2 as KeyValueV2
import qualified Network.VaultTool.TOTP as TOTP
import Network.VaultTool.VaultServerProcess (
    VaultBackendConfig,
    vaultAddress,
    vaultConfigDefaultAddress,
    withVaultConfigFile,
    withVaultServerProcess,
 )

withTempVaultBackend :: (VaultBackendConfig -> IO a) -> IO a
withTempVaultBackend action = withSystemTempDirectory "hs_vault" $ \tmpDir -> do
    let backendConfig = object
            [ "file" .= object
                [ "path" .= tmpDir
                ]
            ]
    action backendConfig

main :: IO ()
main = withTempVaultBackend $ \vaultBackendConfig -> do
    putStrLn "Running tests..."

    vaultExe <- lookupEnv "VAULT_EXE"

    let cfg = vaultConfigDefaultAddress vaultBackendConfig
        addr = vaultAddress cfg
    withVaultConfigFile cfg $ \vaultConfigFile ->
        withVaultServerProcess vaultExe vaultConfigFile addr $
            talkToVault addr

    putStrLn "Ok"

-- | The vault must be a newly created, non-initialized vault
--
-- TODO It would be better to break this into lots of individual unit tests
-- instead of this one big-ass test
talkToVault :: VaultAddress -> IO ()
talkToVault addr = do
    manager <- defaultManager

    let unauthConn = unauthenticatedVaultConnection manager addr

    health <- vaultHealth unauthConn
    _VaultHealth_Initialized health @?= False

    (unsealKeys, rootToken) <- vaultInit unauthConn 4 2

    length unsealKeys @?= 4
    let [key1, key2, key3, _] = unsealKeys

    status0 <- vaultSealStatus unauthConn
    status0 @?= VaultSealStatus
        { _VaultSealStatus_Sealed = True
        , _VaultSealStatus_T = 2
        , _VaultSealStatus_N = 4
        , _VaultSealStatus_Progress = 0
        }

    status1 <- vaultUnseal unauthConn (MasterKey key1)
    status1 @?= VaultSealStatus
        { _VaultSealStatus_Sealed = True
        , _VaultSealStatus_T = 2
        , _VaultSealStatus_N = 4
        , _VaultSealStatus_Progress = 1
        }

    status2 <- vaultUnseal unauthConn Reset
    status2 @?= VaultSealStatus
        { _VaultSealStatus_Sealed = True
        , _VaultSealStatus_T = 2
        , _VaultSealStatus_N = 4
        , _VaultSealStatus_Progress = 0
        }

    status3 <- vaultUnseal unauthConn (MasterKey key2)
    status3 @?= VaultSealStatus
        { _VaultSealStatus_Sealed = True
        , _VaultSealStatus_T = 2
        , _VaultSealStatus_N = 4
        , _VaultSealStatus_Progress = 1
        }

    status4 <- vaultUnseal unauthConn (MasterKey key3)
    status4 @?= VaultSealStatus
        { _VaultSealStatus_Sealed = False
        , _VaultSealStatus_T = 2
        , _VaultSealStatus_N = 4
        , _VaultSealStatus_Progress = 0
        }

    let authConn = authenticatedVaultConnection manager addr rootToken

    vaultNewMount authConn "secret" VaultMount
        { _VaultMount_Type = "kv"
        , _VaultMount_Description = Just "key/value secret storage"
        , _VaultMount_Config = Nothing
        , _VaultMount_Options = Just VaultMountOptions { _VaultMountOptions_Version = Just 2 }
        }

    allMounts <- vaultMounts authConn

    fmap _VaultMount_Type (lookup "cubbyhole/" allMounts) @?= Just "cubbyhole"
    fmap _VaultMount_Type (lookup "secret/" allMounts) @?= Just "kv"
    fmap _VaultMount_Type (lookup "sys/" allMounts) @?= Just "system"

    _ <- vaultMountTune authConn "cubbyhole"
    _ <- vaultMountTune authConn "secret"
    _ <- vaultMountTune authConn "sys"

    vaultNewMount authConn "mymount" VaultMount
        { _VaultMount_Type = "generic"
        , _VaultMount_Description = Just "blah blah blah"
        , _VaultMount_Config = Just VaultMountConfig
            { _VaultMountConfig_DefaultLeaseTtl = Just 42
            , _VaultMountConfig_MaxLeaseTtl = Nothing
            }
        , _VaultMount_Options = Nothing
        }

    mounts2 <- vaultMounts authConn
    fmap _VaultMount_Description (lookup "mymount/" mounts2) @?= Just "blah blah blah"

    t <- vaultMountTune authConn "mymount"
    _VaultMountConfig_DefaultLeaseTtl t @?= 42

    vaultMountSetTune authConn "mymount" VaultMountConfig
        { _VaultMountConfig_DefaultLeaseTtl = Just 52
        , _VaultMountConfig_MaxLeaseTtl = Nothing
        }

    t2 <- vaultMountTune authConn "mymount"
    _VaultMountConfig_DefaultLeaseTtl t2 @?= 52

    vaultUnmount authConn "mymount"

    mounts3 <- vaultMounts authConn
    lookup "mymount/" mounts3 @?= Nothing

    keyValueV2Tests authConn manager addr

    totpTests authConn

    vaultSeal authConn

    status5 <- vaultSealStatus unauthConn
    status5 @?= VaultSealStatus
        { _VaultSealStatus_Sealed = True
        , _VaultSealStatus_T = 2
        , _VaultSealStatus_N = 4
        , _VaultSealStatus_Progress = 0
        }

    health2 <- vaultHealth unauthConn
    _VaultHealth_Initialized health2 @?= True
    _VaultHealth_Sealed health2 @?= True

keyValueV2Tests :: VaultConnection Authenticated -> Manager -> VaultAddress -> IO ()
keyValueV2Tests authConn manager addr = do
    let pathBig = mkVaultSecretPath "big"
    KeyValueV2.vaultWrite authConn pathBig (object ["A" .= 'a', "B" .= 'b'])

    r <- KeyValueV2.vaultRead authConn pathBig
    KeyValueV2.vsvData r @?= object ["A" .= 'a', "B" .= 'b']

    let pathFun = mkVaultSecretPath "fun"
    KeyValueV2.vaultWrite authConn pathFun (FunStuff "fun" [1, 2, 3])
    r2 <- KeyValueV2.vaultRead authConn pathFun
    KeyValueV2.vsvData r2 @?= FunStuff "fun" [1, 2, 3]

    throws (KeyValueV2.vaultRead authConn pathBig :: IO (KeyValueV2.VaultSecretVersion FunStuff)) >>= (@?= True)

    let pathFooBarA = mkVaultSecretPath "foo/bar/a"
        pathFooBarB = mkVaultSecretPath "foo/bar/b"
        pathFooBarABCDEFG = mkVaultSecretPath "foo/bar/a/b/c/d/e/f/g"
        pathFooQuackDuck = mkVaultSecretPath "foo/quack/duck"

    KeyValueV2.vaultWrite authConn pathFooBarA (object ["X" .= 'x'])
    KeyValueV2.vaultWrite authConn pathFooBarB (object ["X" .= 'x'])
    KeyValueV2.vaultWrite authConn pathFooBarABCDEFG (object ["X" .= 'x'])
    KeyValueV2.vaultWrite authConn pathFooQuackDuck (object ["X" .= 'x'])

    let emptySecretPath = mkVaultSecretPath ""
    keys <- KeyValueV2.vaultList authConn emptySecretPath
    assertBool "Secret in list" $ pathBig `elem` keys
    KeyValueV2.vaultDelete authConn pathBig

    keys2 <- KeyValueV2.vaultList authConn emptySecretPath
    assertBool "Secret not in list" $ pathBig `notElem` keys2

    keys3 <- KeyValueV2.vaultListRecursive authConn (mkVaultSecretPath "foo")
    sort keys3 @?= sort
        [ pathFooBarA
        , pathFooBarB
        , pathFooBarABCDEFG
        , pathFooQuackDuck
        ]

    let pathReadVersionTest = mkVaultSecretPath "read/version/secret"
    KeyValueV2.vaultWrite authConn pathReadVersionTest (FunStuff "x" [1])
    KeyValueV2.vaultWrite authConn pathReadVersionTest (FunStuff "y" [2, 3])
    v1Resp <- KeyValueV2.vaultReadVersion authConn pathReadVersionTest (Just 1)
    KeyValueV2.vsvData v1Resp @?= FunStuff "x" [1]
    v2Resp <- KeyValueV2.vaultReadVersion authConn pathReadVersionTest Nothing
    KeyValueV2.vsvData v2Resp @?= FunStuff "y" [2, 3]

    vaultAuthEnable authConn "approle"

    let pathSmall = mkVaultSecretPath "small"
    KeyValueV2.vaultWrite authConn pathSmall (object ["X" .= 'x'])

    vaultPolicyCreate authConn "foo" "path \"secret/small\" { capabilities = [\"read\"] }"

    vaultAppRoleCreate authConn "foo-role" defaultVaultAppRoleParameters{_VaultAppRoleParameters_Policies = ["foo"]}

    roleId <- vaultAppRoleRoleIdRead authConn "foo-role"
    secretId <- _VaultAppRoleSecretIdGenerateResponse_SecretId <$> vaultAppRoleSecretIdGenerate authConn "foo-role" ""

    arConn <- connectToVaultAppRole manager addr roleId secretId
    throws (KeyValueV2.vaultRead arConn pathSmall :: IO (KeyValueV2.VaultSecretVersion FunStuff)) >>= (@?= True)

totpTests :: VaultConnection Authenticated -> IO ()
totpTests authConn = do
    vaultNewMount authConn "totp" VaultMount
        { _VaultMount_Type = "totp"
        , _VaultMount_Description = Just "totp test"
        , _VaultMount_Config = Nothing
        , _VaultMount_Options = Nothing
        }

    let pathTOTP = VaultMountedPath "totp"
        key1 = "key1"
        issuer = "Vault"
        account1 = "test1@test.com"

    genKey <- TOTP.generateKey authConn pathTOTP $ mkGenKeyReq key1 issuer account1
    case parseURI . T.unpack $ TOTP.gkrUrl genKey of
        Nothing -> assertFailure "unable to parse key url"
        Just url -> do
            uriPath url @?= T.unpack ("/" <> issuer <> ":" <> account1)
            let queryArgs = parseQueryString $ uriQuery url
            lookup "algorithm" queryArgs @?= Just "SHA1"
            lookup "digits" queryArgs @?= Just "6"
            lookup "issuer" queryArgs @?= Just (T.unpack issuer)
            lookup "period" queryArgs @?= Just "30"

    key <- TOTP.getKey authConn pathTOTP key1
    TOTP.kAccountName key @?= account1
    TOTP.kAlgorithm key @?= TOTP.SHA1
    TOTP.kDigitCount key @?= TOTP.SixDigits
    TOTP.kIssuer key @?= issuer
    TOTP.kPeriod key @?= 30

    let key2 = "key2"
        account2 = "test2@test.com"
    _ <- TOTP.generateKey authConn pathTOTP $ mkGenKeyReq key2 issuer account2
    keys <- TOTP.listKeys authConn pathTOTP
    sort (TOTP.unKeyNames keys) @?= [key1, key2]

    TOTP.deleteKey authConn pathTOTP key2
    throws (TOTP.getKey authConn pathTOTP key2) >>= (@?= True)

    code <- TOTP.generateCode authConn pathTOTP key1
    validateCodeResp1 <- TOTP.validateCode authConn pathTOTP key1 code
    validateCodeResp1 @?= TOTP.ValidCode

    validateCodeResp2 <- TOTP.validateCode authConn pathTOTP key1 (TOTP.Code "00000")
    validateCodeResp2 @?= TOTP.InvalidCode
  where
    parseQueryString = mapMaybe (toPair . splitOn "=") . splitOn "&" . drop 1
    toPair [x,y] = Just (x, y)
    toPair _ = Nothing
    mkGenKeyReq keyName issuer account = TOTP.mkGenerateKeyRequest keyName issuer account

data FunStuff = FunStuff
    { funString :: String
    , funNumbers :: [Int]
    }
    deriving (Show, Eq, Generic)

instance FromJSON FunStuff
instance ToJSON FunStuff

mkVaultSecretPath :: Text -> VaultSecretPath
mkVaultSecretPath searchPath = VaultSecretPath (VaultMountedPath "secret", VaultSearchPath searchPath)

throws :: IO a -> IO Bool
throws io = catch (io $> False) $ \(_e :: VaultException) -> pure True
