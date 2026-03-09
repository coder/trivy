package parser

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBlockExpandWithSubmoduleOutput(t *testing.T) {
	// `count` meta attributes are incorrectly handled when referencing
	// a module output.
	files := map[string]string{
		"main.tf": `
module "foo" {
	source = "./modules/foo"
}
data "this_resource" "this" {
	count = module.foo.staticZero
}
data "that_resource" "this" {
	count = module.foo.staticFive
}

data "for_each_resource_empty" "this" {
	for_each = module.foo.empty_list
}
data "for_each_resource_abc" "this" {
	for_each = module.foo.list_abc
}

data "dynamic_block" "that" {
	dynamic "element" {
		for_each = module.foo.list_abc
		content {
			foo = element.value
		}
	}
}
`,
		"modules/foo/main.tf": `
output "staticZero" {	
	value = 0
}
output "staticFive" {	
	value = 5
}

output "empty_list" {
	value = []
}
output "list_abc" {
	value = ["a", "b", "c"]
}
`,
	}

	modules := parse(t, files)
	require.Len(t, modules, 2)

	datas := modules.GetDatasByType("this_resource")
	require.Empty(t, datas)

	datas = modules.GetDatasByType("that_resource")
	require.Len(t, datas, 5)

	datas = modules.GetDatasByType("for_each_resource_empty")
	require.Empty(t, datas)

	datas = modules.GetDatasByType("for_each_resource_abc")
	require.Len(t, datas, 3)

	dyn := modules.GetDatasByType("dynamic_block")
	require.Len(t, dyn, 1)
	require.Len(t, dyn[0].GetBlocks("element"), 3, "dynamic expand")
}

func TestBlockExpandWithSubmoduleOutputNested(t *testing.T) {
	files := map[string]string{
		"main.tf": `
module "alpha" {
  source = "./nestedcount"
  set_count = 2
}
module "beta" {
  source = "./nestedcount"
  set_count = module.alpha.set_count
}
module "charlie" {
  count = module.beta.set_count - 1
  source = "./nestedcount"
  set_count = module.beta.set_count
}
data "repeatable" "foo" {
  count = module.charlie[0].set_count
  value = "foo"
}
`,
		"setcount/main.tf": `
variable "set_count" {
    type = number
}
output "set_count" {
  value = var.set_count
}
`,
		"nestedcount/main.tf": `
variable "set_count" {
  type = number
}
module "nested_mod" {
  source = "../setcount"
  set_count = var.set_count
}
output "set_count" {
  value = module.nested_mod.set_count
}
`,
	}

	modules := parse(t, files)
	require.Len(t, modules, 7)

	datas := modules.GetDatasByType("repeatable")
	assert.Len(t, datas, 2)
}

func TestBlockCountModules(t *testing.T) {
	t.Skip(
		"This test is currently failing. " +
			"The count passed to `module bar` is not being set correctly. " +
			"The count value is sourced from the output of `module foo`. " +
			"Submodules cannot be dependent on the output of other submodules right now. ",
	)
	// `count` meta attributes are incorrectly handled when referencing
	// a module output.
	files := map[string]string{
		"main.tf": `
module "foo" {
	source = "./modules/foo"
}
module "bar" {
	source = "./modules/foo"
    count = module.foo.staticZero
}
`,
		"modules/foo/main.tf": `
output "staticZero" {	
	value = 0
}
`,
	}

	modules := parse(t, files)
	require.Len(t, modules, 2)
}
