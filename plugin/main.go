package main

import (
	"log/slog"
)

func Init(authOpts map[string]string, logLevel slog.Level) error {
	//Initialize your plugin with the necessary options
	slog.Info("customPlugin initialized!")
	slog.Debug("Received options", "count", len(authOpts))
	return nil
}

func GetUser(username, password, clientid string) (bool, error) {
	slog.Debug("Checking get user with custom plugin")
	return false, nil
}

func GetSuperuser(username string) (bool, error) {
	slog.Debug("Checking get superuser with custom plugin")
	return false, nil
}

func CheckAcl(username, topic, clientid string, acc int32) (bool, error) {
	slog.Debug("Checking acl with custom plugin")
	return false, nil
}

func GetName() string {
	return "Custom plugin"
}

func Halt() {
	//Do whatever cleanup is needed.
}
