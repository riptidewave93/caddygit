package github

import (
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"

	"github.com/caddyserver/caddy/v2"
	"github.com/go-git/go-git/v5/plumbing"

	"github.com/vrongmeal/caddygit/services/webhook"
)

func init() {
	caddy.RegisterModule(Webhook{})
}

// Webhook implements a hook type which can be used to host the a project
// maintained on Github.
type Webhook struct{}

type pushBody struct {
	Ref string `json:"ref"`
}

type releaseBody struct {
	Action  string `json:"action"`
	Release struct {
		TagName string `json:"tag_name"`
	} `json:"release"`
}

// CaddyModule returns the caddy module information.
func (Webhook) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "git.services.webhook.github",
		New: func() caddy.Module { return new(Webhook) },
	}
}

// Handle implements the webhook.Webhook interface.
func (Webhook) Handle(req *http.Request, hc *webhook.HookConf) (int, error) {
	if err := webhook.ValidateRequest(req); err != nil {
		_, _ = io.Copy(ioutil.Discard, req.Body)
		return http.StatusBadRequest, err
	}

	body, err := ioutil.ReadAll(req.Body)
	if err != nil {
		return http.StatusRequestTimeout, err
	}

	// ensure both the webhook and GitHub agree on the use of a secret
	sig1 := req.Header.Get("X-Hub-Signature")
	sig256 := req.Header.Get("X-Hub-Signature-256")
	if hc.Secret == "" && (sig1 != "" || sig256 != "") {
		return http.StatusInternalServerError, fmt.Errorf("empty webhook secret")
	} else if hc.Secret != "" && sig1 == "" && sig256 == "" {
		return http.StatusBadRequest, fmt.Errorf("empty GitHub secret")
	}

	if hc.Secret != "" {
		var authorized bool
		if sig256 != "" {
			mac := hmac.New(sha256.New, []byte(hc.Secret))
			mac.Write(body)
			authorized = sig256[5:] == hex.EncodeToString(mac.Sum(nil))
		}
		if !authorized && sig1 != "" {
			mac := hmac.New(sha1.New, []byte(hc.Secret))
			mac.Write(body)
			authorized = sig1[5:] == hex.EncodeToString(mac.Sum(nil))
		}
		if !authorized {
			return http.StatusForbidden, fmt.Errorf("invalid signature")
		}
	}

	switch event := req.Header.Get("X-Github-Event"); event {
	case "ping":
	case "push":
		var rBody pushBody

		err = json.Unmarshal(body, &rBody)
		if err != nil {
			return http.StatusBadRequest, err
		}

		refName := plumbing.ReferenceName(rBody.Ref)
		if refName.IsBranch() {
			if refName != hc.RepoInfo.ReferenceName {
				return http.StatusBadRequest, fmt.Errorf("event: push to branch %s", refName)
			}
		} else if refName.IsTag() {
			if !hc.RepoInfo.LatestTag && refName != hc.RepoInfo.ReferenceName {
				return http.StatusBadRequest, fmt.Errorf("event: push to tag %s", refName)
			}
		} else {
			// return error so the repo doesn't update
			return http.StatusBadRequest, fmt.Errorf("refName is neither a tag or a branch")
		}
	case "release":
		var rBody releaseBody

		err = json.Unmarshal(body, &rBody)
		if err != nil {
			return http.StatusBadRequest, err
		}

		if rBody.Release.TagName == "" {
			return http.StatusBadRequest, fmt.Errorf("invalid (empty) tag name")
		}

		if !hc.RepoInfo.LatestTag {
			// When release event, if the repo is not configured to fetch latest tag,
			// don't tick because the other options are either a branch or static tag.
			// in both the cases, a release shouldn't change the tree.
			return http.StatusBadRequest, fmt.Errorf("repo not latest tag")
		}
	case "":
		return http.StatusBadRequest, fmt.Errorf("header 'X-Github-Event' missing")
	default:
		return http.StatusBadRequest, fmt.Errorf("cannot handle %q event", event)
	}

	return http.StatusOK, nil
}

// Interface guards.
var (
	_ caddy.Module    = (*Webhook)(nil)
	_ webhook.Webhook = (*Webhook)(nil)
)
