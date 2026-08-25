package parser

import (
	"io/fs"

	"github.com/zclconf/go-cty/cty"

	"github.com/aquasecurity/trivy/pkg/log"
)

type Option func(p *Parser)

func OptionWithEvalHook(hooks EvaluateStepHook) Option {
	return func(p *Parser) {
		p.stepHooks = append(p.stepHooks, hooks)
	}
}

// OptionWithResourceClosure restricts evaluation of the root module to the
// resource blocks that are actually reachable from the given target block
// types via references. Target types are matched against a block's type label
// (e.g. "coder_parameter"), so both data sources and resources can be targets.
//
// When targetTypes is non-empty, root-module resource blocks that are not in
// the transitive reference closure of the target blocks are excluded before
// evaluation. Every non-resource block (variables, locals, data sources,
// providers, modules, outputs) is always retained, and submodules are
// evaluated in full, so the computed values of the target blocks are
// unchanged. This is a performance optimization for callers that only need a
// subset of a template's output (for example, computing input parameters
// without evaluating the resources a workspace would create).
//
// The closure is conservative: any reference that cannot be resolved to a
// specific block keeps the matching blocks, so a resource is only pruned when
// nothing in the target closure can depend on it. Leaving targetTypes empty
// disables the behavior entirely (default).
func OptionWithResourceClosure(targetTypes []string) Option {
	return func(p *Parser) {
		p.resourceClosureTargets = targetTypes
	}
}

func OptionWithTFVarsPaths(paths ...string) Option {
	return func(p *Parser) {
		p.tfvarsPaths = paths
	}
}

func OptionStopOnHCLError(stop bool) Option {
	return func(p *Parser) {
		p.stopOnHCLError = stop
	}
}

func OptionWithLogger(log *log.Logger) Option {
	return func(p *Parser) {
		p.logger = log
	}
}

func OptionWithWorkingDirectoryPath(cwd string) Option {
	return func(p *Parser) {
		p.cwd = cwd
	}
}

func OptionsWithTfVars(vars map[string]cty.Value) Option {
	return func(p *Parser) {
		p.tfvars = vars
	}
}

func OptionWithWorkspaceName(workspaceName string) Option {
	return func(p *Parser) {
		p.workspaceName = workspaceName
	}
}

func OptionWithDownloads(allowed bool) Option {
	return func(p *Parser) {
		p.allowDownloads = allowed
	}
}

func OptionWithSkipCachedModules(b bool) Option {
	return func(p *Parser) {
		p.skipCachedModules = b
	}
}

func OptionWithConfigsFS(fsys fs.FS) Option {
	return func(p *Parser) {
		p.configsFS = fsys
	}
}

func OptionWithSkipFiles(files []string) Option {
	return func(p *Parser) {
		p.skipPaths = files
	}
}

func OptionWithSkipDirs(dirs []string) Option {
	return func(p *Parser) {
		p.skipPaths = dirs
	}
}
