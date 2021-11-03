{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}

module Main where

import Control.Exception (catch)
import Data.Aeson
import Data.Functor (($>))
import Data.List (sort)
import Data.Text (Text)
import GHC.Generics
import System.Environment
import System.IO.Temp (withSystemTempDirectory)
import Test.Tasty.HUnit

import Network.VaultTool
import Network.VaultTool.KeyValueV2
import Network.VaultTool.VaultServerProcess

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

    let unauthConn = UnauthenticatedVaultConnection manager addr

    health <- vaultHealth unauthConn
    _VaultHealth_Initialized health @?= False

    (unsealKeys, rootToken) <- vaultInit unauthConn 4 2

    length unsealKeys @?= 4

    status0 <- vaultSealStatus unauthConn
    status0 @?= VaultSealStatus
        { _VaultSealStatus_Sealed = True
        , _VaultSealStatus_T = 2
        , _VaultSealStatus_N = 4
        , _VaultSealStatus_Progress = 0
        }

    status1 <- vaultUnseal unauthConn (VaultUnseal_Key (unsealKeys !! 0))
    status1 @?= VaultSealStatus
        { _VaultSealStatus_Sealed = True
        , _VaultSealStatus_T = 2
        , _VaultSealStatus_N = 4
        , _VaultSealStatus_Progress = 1
        }

    status2 <- vaultUnseal unauthConn VaultUnseal_Reset
    status2 @?= VaultSealStatus
        { _VaultSealStatus_Sealed = True
        , _VaultSealStatus_T = 2
        , _VaultSealStatus_N = 4
        , _VaultSealStatus_Progress = 0
        }

    status3 <- vaultUnseal unauthConn (VaultUnseal_Key (unsealKeys !! 1))
    status3 @?= VaultSealStatus
        { _VaultSealStatus_Sealed = True
        , _VaultSealStatus_T = 2
        , _VaultSealStatus_N = 4
        , _VaultSealStatus_Progress = 1
        }

    status4 <- vaultUnseal unauthConn (VaultUnseal_Key (unsealKeys !! 2))
    status4 @?= VaultSealStatus
        { _VaultSealStatus_Sealed = False
        , _VaultSealStatus_T = 2
        , _VaultSealStatus_N = 4
        , _VaultSealStatus_Progress = 0
        }

    let authConn = AuthenticatedVaultConnection manager addr rootToken

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

    let pathBig = mkVaultSecretPath "big"
    vaultWrite authConn pathBig (object ["A" .= 'a', "B" .= 'b'])

    r <- vaultRead authConn pathBig
    vsvData r @?= object ["A" .= 'a', "B" .= 'b']

    let pathFun = mkVaultSecretPath "fun"
    vaultWrite authConn pathFun (FunStuff "fun" [1, 2, 3])
    r2 <- vaultRead authConn pathFun
    vsvData r2 @?= (FunStuff "fun" [1, 2, 3])

    throws (vaultRead authConn pathBig :: IO (VaultSecretVersion FunStuff)) >>= (@?= True)

    let pathFooBarA = mkVaultSecretPath "foo/bar/a"
        pathFooBarB = mkVaultSecretPath "foo/bar/b"
        pathFooBarABCDEFG = mkVaultSecretPath "foo/bar/a/b/c/d/e/f/g"
        pathFooQuackDuck = mkVaultSecretPath "foo/quack/duck"

    vaultWrite authConn pathFooBarA (object ["X" .= 'x'])
    vaultWrite authConn pathFooBarB (object ["X" .= 'x'])
    vaultWrite authConn pathFooBarABCDEFG (object ["X" .= 'x'])
    vaultWrite authConn pathFooQuackDuck (object ["X" .= 'x'])

    let emptySecretPath = mkVaultSecretPath ""
    keys <- vaultList authConn emptySecretPath
    assertBool "Secret in list" $ pathBig `elem` keys
    vaultDelete authConn pathBig

    keys2 <- vaultList authConn emptySecretPath
    assertBool "Secret not in list" $ not (pathBig `elem` keys2)

    keys3 <- vaultListRecursive authConn (mkVaultSecretPath "foo")
    sort keys3 @?= sort
        [ pathFooBarA
        , pathFooBarB
        , pathFooBarABCDEFG
        , pathFooQuackDuck
        ]

    vaultAuthEnable authConn "approle"

    let pathSmall = mkVaultSecretPath "small"
    vaultWrite authConn pathSmall (object ["X" .= 'x'])

    vaultPolicyCreate authConn "foo" "path \"secret/small\" { capabilities = [\"read\"] }"

    vaultAppRoleCreate authConn "foo-role" defaultVaultAppRoleParameters{_VaultAppRoleParameters_Policies = ["foo"]}

    roleId <- vaultAppRoleRoleIdRead authConn "foo-role"
    secretId <- _VaultAppRoleSecretIdGenerateResponse_SecretId <$> vaultAppRoleSecretIdGenerate authConn "foo-role" ""

    arConn <- connectToVaultAppRole manager addr roleId secretId
    throws (vaultRead arConn pathSmall :: IO (VaultSecretVersion FunStuff)) >>= (@?= True)

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
