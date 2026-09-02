package parser

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/internal/testutil"
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
