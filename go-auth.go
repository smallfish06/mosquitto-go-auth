package main

import "C"

import (
	"context"
	"io"
	"log/slog"
	"os"
	"strconv"
	"strings"
	"time"

	bes "github.com/smallfish06/mosquitto-go-auth/backends"
	"github.com/smallfish06/mosquitto-go-auth/cache"
	"github.com/smallfish06/mosquitto-go-auth/hashing"
)

type AuthPlugin struct {
	backends              *bes.Backends
	useCache              bool
	logLevel              slog.Level
	logDest               string
	logFile               string
	ctx                   context.Context
	cache                 cache.Store
	hasher                hashing.HashComparer
	retryCount            int
	useClientidAsUsername bool
}

// errors to signal mosquitto
const (
	AuthRejected = 0
	AuthGranted  = 1
	AuthError    = 2
)

var authOpts map[string]string // Options passed by mosquitto.
var authPlugin AuthPlugin      // General struct with options and conf.

//export AuthPluginInit
func AuthPluginInit(keys []*C.char, values []*C.char, authOptsNum int, version *C.char) {
	// Initialize auth plugin struct with default and given values.
	authPlugin = AuthPlugin{
		logLevel: slog.LevelInfo,
		ctx:      context.Background(),
	}

	authOpts = make(map[string]string)
	for i := 0; i < authOptsNum; i++ {
		authOpts[C.GoString(keys[i])] = C.GoString(values[i])
	}

	if retryCount, ok := authOpts["retry_count"]; ok {
		retry, err := strconv.ParseInt(retryCount, 10, 64)
		if err == nil {
			authPlugin.retryCount = int(retry)
		} else {
			slog.Warn("couldn't parse retryCount, defaulting to 0", "error", err)
		}
	}

	if useClientidAsUsername, ok := authOpts["use_clientid_as_username"]; ok && strings.Replace(useClientidAsUsername, " ", "", -1) == "true" {
		slog.Info("clientid will be used as username on checks")
		authPlugin.useClientidAsUsername = true
	} else {
		authPlugin.useClientidAsUsername = false
	}

	// Check if log level is given. Set level if any valid option is given.
	if logLevel, ok := authOpts["log_level"]; ok {
		logLevel = strings.Replace(logLevel, " ", "", -1)
		switch logLevel {
		case "debug":
			authPlugin.logLevel = slog.LevelDebug
		case "info":
			authPlugin.logLevel = slog.LevelInfo
		case "warn":
			authPlugin.logLevel = slog.LevelWarn
		case "error":
			authPlugin.logLevel = slog.LevelError
		default:
			slog.Info("log_level unkwown, using default info level")
		}
	}

	var logWriter io.Writer = os.Stderr
	if logDest, ok := authOpts["log_dest"]; ok {
		switch logDest {
		case "stdout":
			logWriter = os.Stdout
		case "file":
			if logFile, ok := authOpts["log_file"]; ok {
				file, err := os.OpenFile(logFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
				if err == nil {
					logWriter = file
				} else {
					slog.Error("failed to log to file, using default stderr", "error", err)
				}
			}
		default:
			slog.Info("log_dest unknown, using default stderr")
		}
	}

	// Set up slog with the configured output and level
	handler := slog.NewTextHandler(logWriter, &slog.HandlerOptions{
		Level: authPlugin.logLevel,
	})
	slog.SetDefault(slog.New(handler))

	var err error

	authPlugin.backends, err = bes.Initialize(authOpts, authPlugin.logLevel, C.GoString(version))
	if err != nil {
		slog.Error("error initializing backends", "error", err)
		os.Exit(1)
	}

	if cache, ok := authOpts["cache"]; ok && strings.Replace(cache, " ", "", -1) == "true" {
		slog.Info("redisCache activated")
		authPlugin.useCache = true
	} else {
		slog.Info("No cache set.")
		authPlugin.useCache = false
	}

	if authPlugin.useCache {
		setCache(authOpts)
	}
}

func setCache(authOpts map[string]string) {

	var aclCacheSeconds int64 = 30
	var authCacheSeconds int64 = 30
	var authJitterSeconds int64 = 0
	var aclJitterSeconds int64 = 0

	if authCacheSec, ok := authOpts["auth_cache_seconds"]; ok {
		authSec, err := strconv.ParseInt(authCacheSec, 10, 64)
		if err == nil {
			authCacheSeconds = authSec
		} else {
			slog.Warn("couldn't parse authCacheSeconds, using default", "error", err, "default", authCacheSeconds)
		}
	}

	if authJitterSec, ok := authOpts["auth_jitter_seconds"]; ok {
		authSec, err := strconv.ParseInt(authJitterSec, 10, 64)
		if err == nil {
			authJitterSeconds = authSec
		} else {
			slog.Warn("couldn't parse authJitterSeconds, using default", "error", err, "default", authJitterSeconds)
		}
	}

	if authJitterSeconds > authCacheSeconds {
		authJitterSeconds = authCacheSeconds
		slog.Warn("authJitterSeconds is larger than authCacheSeconds, using default", "value", authJitterSeconds)
	}

	if aclCacheSec, ok := authOpts["acl_cache_seconds"]; ok {
		aclSec, err := strconv.ParseInt(aclCacheSec, 10, 64)
		if err == nil {
			aclCacheSeconds = aclSec
		} else {
			slog.Warn("couldn't parse aclCacheSeconds, using default", "error", err, "default", aclCacheSeconds)
		}
	}

	if aclJitterSec, ok := authOpts["acl_jitter_seconds"]; ok {
		aclSec, err := strconv.ParseInt(aclJitterSec, 10, 64)
		if err == nil {
			aclJitterSeconds = aclSec
		} else {
			slog.Warn("couldn't parse aclJitterSeconds, using default", "error", err, "default", aclJitterSeconds)
		}
	}

	if aclJitterSeconds > aclCacheSeconds {
		aclJitterSeconds = aclCacheSeconds
		slog.Warn("aclJitterSeconds is larger than aclCacheSeconds, using default", "value", aclJitterSeconds)
	}

	reset := false
	if cacheReset, ok := authOpts["cache_reset"]; ok && cacheReset == "true" {
		reset = true
	}

	refreshExpiration := false
	if refresh, ok := authOpts["cache_refresh"]; ok && refresh == "true" {
		refreshExpiration = true
	}

	switch authOpts["cache_type"] {
	case "redis":
		host := "localhost"
		port := "6379"
		db := 3
		password := ""
		cluster := false

		if authOpts["cache_mode"] == "true" {
			cluster = true
		}

		if cachePassword, ok := authOpts["cache_password"]; ok {
			password = cachePassword
		}

		if cluster {

			addressesOpt := authOpts["redis_cluster_addresses"]
			if addressesOpt == "" {
				slog.Error("cache Redis cluster addresses missing, defaulting to no cache.")
				authPlugin.useCache = false
				return
			}

			// Take the given addresses and trim spaces from them.
			addresses := strings.Split(addressesOpt, ",")
			for i := 0; i < len(addresses); i++ {
				addresses[i] = strings.TrimSpace(addresses[i])
			}

			authPlugin.cache = cache.NewRedisClusterStore(
				password,
				addresses,
				time.Duration(authCacheSeconds)*time.Second,
				time.Duration(aclCacheSeconds)*time.Second,
				time.Duration(authJitterSeconds)*time.Second,
				time.Duration(aclJitterSeconds)*time.Second,
				refreshExpiration,
			)

		} else {
			if cacheHost, ok := authOpts["cache_host"]; ok {
				host = cacheHost
			}

			if cachePort, ok := authOpts["cache_port"]; ok {
				port = cachePort
			}

			if cacheDB, ok := authOpts["cache_db"]; ok {
				parsedDB, err := strconv.ParseInt(cacheDB, 10, 32)
				if err == nil {
					db = int(parsedDB)
				} else {
					slog.Warn("couldn't parse cache db, using default", "error", err, "default", db)
				}
			}

			authPlugin.cache = cache.NewSingleRedisStore(
				host,
				port,
				password,
				db,
				time.Duration(authCacheSeconds)*time.Second,
				time.Duration(aclCacheSeconds)*time.Second,
				time.Duration(authJitterSeconds)*time.Second,
				time.Duration(aclJitterSeconds)*time.Second,
				refreshExpiration,
			)
		}

	default:
		authPlugin.cache = cache.NewGoStore(
			time.Duration(authCacheSeconds)*time.Second,
			time.Duration(aclCacheSeconds)*time.Second,
			time.Duration(authJitterSeconds)*time.Second,
			time.Duration(aclJitterSeconds)*time.Second,
			refreshExpiration,
		)
	}

	if !authPlugin.cache.Connect(authPlugin.ctx, reset) {
		authPlugin.cache = nil
		authPlugin.useCache = false
		slog.Info("couldn't start cache, defaulting to no cache")
	}

}

//export AuthUnpwdCheck
func AuthUnpwdCheck(username, password, clientid *C.char) uint8 {
	var ok bool
	var err error

	for try := 0; try <= authPlugin.retryCount; try++ {
		ok, err = authUnpwdCheck(C.GoString(username), C.GoString(password), C.GoString(clientid))
		if err == nil {
			break
		}
	}

	if err != nil {
		slog.Error("authentication error", "error", err)
		return AuthError
	}

	if ok {
		return AuthGranted
	}

	return AuthRejected
}

func authUnpwdCheck(username, password, clientid string) (bool, error) {
	var authenticated bool
	var cached bool
	var granted bool
	var err error

	username = setUsername(username, clientid)

	if authPlugin.useCache {
		slog.Debug("checking auth cache", "username", username)
		cached, granted = authPlugin.cache.CheckAuthRecord(authPlugin.ctx, username, password)
		if cached {
			slog.Debug("found in cache", "username", username)
			return granted, nil
		}
	}

	authenticated, err = authPlugin.backends.AuthUnpwdCheck(username, password, clientid)

	if authPlugin.useCache && err == nil {
		authGranted := "false"
		if authenticated {
			authGranted = "true"
		}
		slog.Debug("setting auth cache", "username", username)
		if setAuthErr := authPlugin.cache.SetAuthRecord(authPlugin.ctx, username, password, authGranted); setAuthErr != nil {
			slog.Error("set auth cache", "error", setAuthErr)
			return false, setAuthErr
		}
	}
	return authenticated, err
}

//export AuthAclCheck
func AuthAclCheck(clientid, username, topic *C.char, acc C.int) uint8 {
	var ok bool
	var err error

	for try := 0; try <= authPlugin.retryCount; try++ {
		ok, err = authAclCheck(C.GoString(clientid), C.GoString(username), C.GoString(topic), int(acc))
		if err == nil {
			break
		}
	}

	if err != nil {
		slog.Error("acl check error", "error", err)
		return AuthError
	}

	if ok {
		return AuthGranted
	}

	return AuthRejected
}

func authAclCheck(clientid, username, topic string, acc int) (bool, error) {
	var aclCheck bool
	var cached bool
	var granted bool
	var err error

	username = setUsername(username, clientid)

	if authPlugin.useCache {
		slog.Debug("checking acl cache", "username", username)
		cached, granted = authPlugin.cache.CheckACLRecord(authPlugin.ctx, username, topic, clientid, acc)
		if cached {
			slog.Debug("found in cache", "username", username)
			return granted, nil
		}
	}

	aclCheck, err = authPlugin.backends.AuthAclCheck(clientid, username, topic, acc)

	if authPlugin.useCache && err == nil {
		authGranted := "false"
		if aclCheck {
			authGranted = "true"
		}
		slog.Debug("setting acl cache", "granted", authGranted, "username", username)
		if setACLErr := authPlugin.cache.SetACLRecord(authPlugin.ctx, username, topic, clientid, acc, authGranted); setACLErr != nil {
			slog.Error("set acl cache", "error", setACLErr)
			return false, setACLErr
		}
	}

	slog.Debug("acl check result", "granted", aclCheck, "username", username)
	return aclCheck, err
}

//export AuthPskKeyGet
func AuthPskKeyGet() bool {
	return true
}

//export AuthPluginCleanup
func AuthPluginCleanup() {
	slog.Info("Cleaning up plugin")
	// If cache is set, close cache connection.
	if authPlugin.cache != nil {
		authPlugin.cache.Close()
	}

	authPlugin.backends.Halt()
}

func setUsername(username, clientid string) string {
	if authPlugin.useClientidAsUsername {
		return clientid
	}

	return username
}

func main() {}
