package git

import (
	// Submodules for the git app module registered here
	_ "github.com/riptidewave93/caddygit/services/poll"
	_ "github.com/riptidewave93/caddygit/services/webhook"
	_ "github.com/riptidewave93/caddygit/services/webhook/generic"
	_ "github.com/riptidewave93/caddygit/services/webhook/github"
)
