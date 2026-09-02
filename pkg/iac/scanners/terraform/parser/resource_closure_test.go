package parser

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/internal/testutil"
	"github.com/aquasecurity/trivy/pkg/iac/terraform"
)

// A resource referenced by a parameter (transitively, through a local) must be
// retained, while a resource nothing in the target closure references must be
// pruned. Crucially, the parameter's computed value must be identical with and
// without pruning.
const resourceClosureFixture = `
data "coder_parameter" "flavor" {
  name    = "flavor"
  default = local.from_resource
}

locals {
  from_resource = my_resource.referenced.name
}

resource "my_resource" "referenced" {
  name = "large"
}

resource "my_resource" "orphan" {
  name = "unused"
}
`

func Test_OptionWithResourceClosure_PrunesOrphanKeepsReferenced(t *testing.T) {
	fs := testutil.CreateFS(map[string]string{"main.tf": resourceClosureFixture})

	parser := New(fs, "",
		OptionStopOnHCLError(true),
		OptionWithResourceClosure([]string{"coder_parameter"}),
	)
	require.NoError(t, parser.ParseFS(t.Context(), "."))

	modules, err := parser.EvaluateAll(t.Context())
	require.NoError(t, err)
	require.Len(t, modules, 1)
	root := modules[0]

	// The orphan resource is pruned; the one reachable from the parameter is kept.
	resources := root.GetResourcesByType("my_resource")
	require.Len(t, resources, 1)
	assert.Equal(t, "referenced", resources[0].NameLabel())

	// The parameter's default is unchanged: it still resolves through the
	// retained resource.
	params := root.GetDatasByType("coder_parameter")
	require.Len(t, params, 1)
	assert.Equal(t, "large", params[0].GetAttribute("default").Value().AsString())
}

func Test_OptionWithResourceClosure_DisabledByDefault(t *testing.T) {
	fs := testutil.CreateFS(map[string]string{"main.tf": resourceClosureFixture})

	parser := New(fs, "", OptionStopOnHCLError(true))
	require.NoError(t, parser.ParseFS(t.Context(), "."))

	modules, err := parser.EvaluateAll(t.Context())
	require.NoError(t, err)
	require.Len(t, modules, 1)
	root := modules[0]

	// Without the option, both resources are evaluated as normal.
	assert.Len(t, root.GetResourcesByType("my_resource"), 2)
	params := root.GetDatasByType("coder_parameter")
	require.Len(t, params, 1)
	assert.Equal(t, "large", params[0].GetAttribute("default").Value().AsString())
}

func Test_OptionWithResourceClosure_NoTargetPresentKeepsEverything(t *testing.T) {
	fs := testutil.CreateFS(map[string]string{"main.tf": resourceClosureFixture})

	// The target type is absent from the template, so there is no basis to
	// prune: everything must be retained.
	parser := New(fs, "",
		OptionStopOnHCLError(true),
		OptionWithResourceClosure([]string{"coder_workspace_preset"}),
	)
	require.NoError(t, parser.ParseFS(t.Context(), "."))

	modules, err := parser.EvaluateAll(t.Context())
	require.NoError(t, err)
	require.Len(t, modules, 1)

	assert.Len(t, modules[0].GetResourcesByType("my_resource"), 2)
}

// A resource referenced only through an index expression (count or for_each)
// must still be retained. Pruning runs before count/for_each expansion, so the
// resource block carries no key while the reference does; matching must not
// treat that mismatch as "different block".
func Test_OptionWithResourceClosure_IndexedReferenceRetained(t *testing.T) {
	tests := []struct {
		name     string
		meta     string
		refIndex string
	}{
		{name: "count", meta: `count = 1`, refIndex: `[0]`},
		{name: "for_each", meta: `for_each = toset(["a"])`, refIndex: `["a"]`},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			fixture := `
data "coder_parameter" "flavor" {
  name    = "flavor"
  default = local.from_resource
}

locals {
  from_resource = my_resource.indexed` + tc.refIndex + `.name
}

resource "my_resource" "indexed" {
  ` + tc.meta + `
  name = "large"
}
`
			fs := testutil.CreateFS(map[string]string{"main.tf": fixture})

			parser := New(fs, "",
				OptionStopOnHCLError(true),
				OptionWithResourceClosure([]string{"coder_parameter"}),
			)
			require.NoError(t, parser.ParseFS(t.Context(), "."))

			modules, err := parser.EvaluateAll(t.Context())
			require.NoError(t, err)
			require.Len(t, modules, 1)
			root := modules[0]

			// The resource is in the parameter's closure and must survive pruning.
			require.Len(t, root.GetResourcesByType("my_resource"), 1)

			// And the parameter's default must be identical to an unpruned run.
			params := root.GetDatasByType("coder_parameter")
			require.Len(t, params, 1)
			def := params[0].GetAttribute("default").Value()
			require.True(t, def.IsKnown() && !def.IsNull(), "parameter default became unknown after pruning")
			assert.Equal(t, "large", def.AsString())
		})
	}
}

// hasResourceNamed reports whether any my_resource block with the given name
// label survives in the module (count/for_each expands into multiple blocks
// that share a name label).
func hasResourceNamed(root *terraform.Module, name string) bool {
	for _, r := range root.GetResourcesByType("my_resource") {
		if r.NameLabel() == name {
			return true
		}
	}
	return false
}

// A splat reference (my_resource.web[*].name) names the resource without a
// concrete key, so the base block must be retained.
func Test_OptionWithResourceClosure_SplatReferenceRetained(t *testing.T) {
	fixture := `
data "coder_parameter" "flavor" {
  name    = "flavor"
  default = local.joined
}

locals {
  joined = join(",", my_resource.web[*].name)
}

resource "my_resource" "web" {
  count = 2
  name  = "large"
}

resource "my_resource" "orphan" {
  name = "unused"
}
`
	fs := testutil.CreateFS(map[string]string{"main.tf": fixture})

	parser := New(fs, "",
		OptionStopOnHCLError(true),
		OptionWithResourceClosure([]string{"coder_parameter"}),
	)
	require.NoError(t, parser.ParseFS(t.Context(), "."))

	modules, err := parser.EvaluateAll(t.Context())
	require.NoError(t, err)
	require.Len(t, modules, 1)
	root := modules[0]

	// Orphan (a plain resource) is pruned. The splat-referenced resource is
	// retained and evaluated, proven by the parameter default resolving to the
	// joined names rather than becoming unknown.
	assert.False(t, hasResourceNamed(root, "orphan"), "orphan resource should have been pruned")

	params := root.GetDatasByType("coder_parameter")
	require.Len(t, params, 1)
	def := params[0].GetAttribute("default").Value()
	require.True(t, def.IsKnown() && !def.IsNull(), "parameter default became unknown after pruning (splat resource pruned)")
	assert.Equal(t, "large,large", def.AsString())
}

// A reference indexed by a variable (my_resource.pool[var.idx]) cannot be
// statically resolved to a key, but the base resource must still be retained.
func Test_OptionWithResourceClosure_DynamicIndexReferenceRetained(t *testing.T) {
	fixture := `
variable "idx" {
  default = 1
}

data "coder_parameter" "flavor" {
  name    = "flavor"
  default = my_resource.pool[var.idx].name
}

resource "my_resource" "pool" {
  count = 2
  name  = "large"
}

resource "my_resource" "orphan" {
  name = "unused"
}
`
	fs := testutil.CreateFS(map[string]string{"main.tf": fixture})

	parser := New(fs, "",
		OptionStopOnHCLError(true),
		OptionWithResourceClosure([]string{"coder_parameter"}),
	)
	require.NoError(t, parser.ParseFS(t.Context(), "."))

	modules, err := parser.EvaluateAll(t.Context())
	require.NoError(t, err)
	require.Len(t, modules, 1)
	root := modules[0]

	// Orphan (a plain resource) is pruned. The dynamically-indexed resource is
	// retained and evaluated, proven by the parameter default resolving.
	assert.False(t, hasResourceNamed(root, "orphan"), "orphan resource should have been pruned")

	params := root.GetDatasByType("coder_parameter")
	require.Len(t, params, 1)
	def := params[0].GetAttribute("default").Value()
	require.True(t, def.IsKnown() && !def.IsNull(), "parameter default became unknown after pruning (indexed resource pruned)")
	assert.Equal(t, "large", def.AsString())
}

// A reference inside a parameter's nested block (an option value here) must be
// followed: blockReferences recurses nested blocks, so the resource is kept.
func Test_OptionWithResourceClosure_NestedBlockReferenceRetained(t *testing.T) {
	fixture := `
data "coder_parameter" "flavor" {
  name = "flavor"

  option {
    name  = "only"
    value = my_resource.x.name
  }
}

resource "my_resource" "x" {
  name = "large"
}

resource "my_resource" "orphan" {
  name = "unused"
}
`
	fs := testutil.CreateFS(map[string]string{"main.tf": fixture})

	parser := New(fs, "",
		OptionStopOnHCLError(true),
		OptionWithResourceClosure([]string{"coder_parameter"}),
	)
	require.NoError(t, parser.ParseFS(t.Context(), "."))

	modules, err := parser.EvaluateAll(t.Context())
	require.NoError(t, err)
	require.Len(t, modules, 1)
	root := modules[0]

	assert.True(t, hasResourceNamed(root, "x"), "resource referenced from a nested option block was pruned")
	assert.False(t, hasResourceNamed(root, "orphan"), "orphan resource should have been pruned")
}

// A resource referenced only through a module input argument must be retained:
// the module block is part of the frontier, so its references seed the closure.
func Test_OptionWithResourceClosure_ModuleArgReferenceRetained(t *testing.T) {
	files := map[string]string{
		"main.tf": `
data "coder_parameter" "flavor" {
  name    = "flavor"
  default = "x"
}

module "m" {
  source = "./mod"
  in     = my_resource.shared.name
}

resource "my_resource" "shared" {
  name = "large"
}

resource "my_resource" "orphan" {
  name = "unused"
}
`,
		"mod/main.tf": `
variable "in" {
  type = string
}

output "out" {
  value = var.in
}
`,
	}
	fs := testutil.CreateFS(files)

	parser := New(fs, "",
		OptionStopOnHCLError(true),
		OptionWithResourceClosure([]string{"coder_parameter"}),
	)
	require.NoError(t, parser.ParseFS(t.Context(), "."))

	modules, err := parser.EvaluateAll(t.Context())
	require.NoError(t, err)
	require.GreaterOrEqual(t, len(modules), 1)
	root := modules[0]

	assert.True(t, hasResourceNamed(root, "shared"), "resource referenced via a module argument was pruned")
	assert.False(t, hasResourceNamed(root, "orphan"), "orphan resource should have been pruned")
}
