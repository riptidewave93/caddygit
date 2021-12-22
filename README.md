# caddygit

### Note that this is a fork-of-a-fork that is only modified to allow import during docker build. This code IS NOT OWNED OR MANAGED by me in any way, shape, or form. Please refer to the source repos.

> Git module for Caddy v2

The module is helpful in creating git clients that pull from the given
repository at regular intervals of time (poll service) or whenever there
is a change in the repository (webhook service). On a successful pull
it runs the specified commands to automate deployment.

## Installation

Simply add the following import to
[`cmd/caddy/main.go`](https://github.com/caddyserver/caddy/blob/master/cmd/caddy/main.go)
and build the caddy binary:

```go
package main

import (
	caddycmd "github.com/caddyserver/caddy/v2/cmd"

	// plug in Caddy modules here
	_ "github.com/caddyserver/caddy/v2/modules/standard"
	_ "github.com/riptidewave93/caddygit/module/git" // Yay!!!
)

func main() {
	caddycmd.Main()
}
```

**OR** you can use [xcaddy](https://github.com/caddyserver/xcaddy) to build:

```bash
$ xcaddy build v2.1.1 \
    --with github.com/riptidewave93/caddygit/module/git
```

## API structure

```jsonc
{
    // Your caddy apps.
    "apps": {
        // Git app module.
        "git": {
            // Your git clients to be deployed.
            "clients": [
                // Example client.
                {
                    // Git repository info.
                    "repo": {
                        // HTTP URL of the git repository.
                        "url": "http://github.com/riptidewave93/caddygit",

                        // Path to clone the repository in. If path specified
                        // exists and is a git repository, it simply opens the
                        // repo. If the path is not a repo and does not exist,
                        // it creates a repo in that path.
                        "path": "/path/to/clone",

                        // Branch (or tag) of the repository to clone. Defaults
                        // to `master`.
                        "branch": "my-branch",

                        // Username and secret for authentication of private
                        // repositories. If authenticating via access token,
                        // set the auth_secret equal to the value of access token
                        // and auth_user can be omitted.
                        "auth_user": "vrongmeal",
                        "auth_secret": "password",

                        // Specifies whether to clone only the specified branch.
                        "single_branch": true,

                        // Depth of commits to fetch.
                        "depth": 1
                    },
                    // Service info.
                    "service": {
                        // Type of the service.
                        // Services supported: poll, webhook
                        "type": "poll",

                        // Interval after which service will tick.
                        "interval": "10m"
                    },
                    // Commands to run after every update.
                    "commands_after": [
                        {
                            // Command to execute.
                            "command": ["echo", "hello world"],

                            // Whether to run command in background (async).
                            // Defaults to false.
                            "async": true
                        }
                    ]
                }
            ]
        }
    }
}
```

## Caddyfile

For a seamless transition from [Git module for Caddy v1](https://github.com/abiosoft/caddy-git), support for Caddyfile was added in a similar fashion:

    git repo [path]

For more control use the following syntax (bear in mind, this options are different from v1):

    git [<repo>] [<path>] {
        repo|url          <repo>
        path              <path>
        branch            <branch>
        auth_user         <username>
        auth_secret       <password>
        single_branch     true|false
        depth             <depth>
        service_type      <service type>
        service_interval  <service interval>
        command_after     <command>
        command_async     true|false
    }

- repo is the URL to the repository
- path is the path to clone the repository into; default is site root. It can be absolute or relative (to site root).
- branch is the branch or tag to pull; default is master branch.

## TODO:

- [X] Support for Caddyfile
- [x] Webhook service
