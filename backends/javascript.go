package backends

import (
	"log/slog"
	"strconv"

	"github.com/pkg/errors"
	"github.com/smallfish06/mosquitto-go-auth/backends/js"
)

type Javascript struct {
	stackDepthLimit int
	msMaxDuration   int64

	userScript      string
	superuserScript string
	aclScript       string

	runner *js.Runner
}

func NewJavascript(authOpts map[string]string, logLevel slog.Level) (*Javascript, error) {

	javascript := &Javascript{
		stackDepthLimit: js.DefaultStackDepthLimit,
		msMaxDuration:   js.DefaultMsMaxDuration,
	}

	jsOk := true
	missingOptions := ""

	if stackLimit, ok := authOpts["js_stack_depth_limit"]; ok {
		limit, err := strconv.ParseInt(stackLimit, 10, 64)
		if err != nil {
			slog.Error("invalid stack depth limit, using default", "value", stackLimit, "default", js.DefaultStackDepthLimit)
		} else {
			javascript.stackDepthLimit = int(limit)
		}
	}

	if maxDuration, ok := authOpts["js_ms_max_duration"]; ok {
		duration, err := strconv.ParseInt(maxDuration, 10, 64)
		if err != nil {
			slog.Error("invalid max duration, using default", "value", maxDuration, "default", js.DefaultMsMaxDuration)
		} else {
			javascript.msMaxDuration = duration
		}
	}

	if userScriptPath, ok := authOpts["js_user_script_path"]; ok {
		script, err := js.LoadScript(userScriptPath)
		if err != nil {
			return javascript, err
		}

		javascript.userScript = script
	} else {
		jsOk = false
		missingOptions += " js_user_script_path"
	}

	if superuserScriptPath, ok := authOpts["js_superuser_script_path"]; ok {
		script, err := js.LoadScript(superuserScriptPath)
		if err != nil {
			return javascript, err
		}

		javascript.superuserScript = script
	} else {
		jsOk = false
		missingOptions += " js_superuser_script_path"
	}

	if aclScriptPath, ok := authOpts["js_acl_script_path"]; ok {
		script, err := js.LoadScript(aclScriptPath)
		if err != nil {
			return javascript, err
		}

		javascript.aclScript = script
	} else {
		jsOk = false
		missingOptions += " js_acl_script_path"
	}

	// Exit if any mandatory option is missing.
	if !jsOk {
		return nil, errors.Errorf("Javascript backend error: missing options: %s", missingOptions)
	}

	javascript.runner = js.NewRunner(javascript.stackDepthLimit, javascript.msMaxDuration)

	return javascript, nil
}

func (o *Javascript) GetUser(username, password, clientid string) (bool, error) {
	params := map[string]interface{}{
		"username": username,
		"password": password,
		"clientid": clientid,
	}

	granted, err := o.runner.RunScript(o.userScript, params)
	if err != nil {
		slog.Error("js error", "error", err)
	}

	return granted, err
}

func (o *Javascript) GetSuperuser(username string) (bool, error) {
	params := map[string]interface{}{
		"username": username,
	}

	granted, err := o.runner.RunScript(o.superuserScript, params)
	if err != nil {
		slog.Error("js error", "error", err)
	}

	return granted, err
}

func (o *Javascript) CheckAcl(username, topic, clientid string, acc int32) (bool, error) {
	params := map[string]interface{}{
		"username": username,
		"topic":    topic,
		"clientid": clientid,
		"acc":      acc,
	}

	granted, err := o.runner.RunScript(o.aclScript, params)
	if err != nil {
		slog.Error("js error", "error", err)
	}

	return granted, err
}

// GetName returns the backend's name
func (o *Javascript) GetName() string {
	return "Javascript"
}

func (o *Javascript) Halt() {
	// NO-OP
}
