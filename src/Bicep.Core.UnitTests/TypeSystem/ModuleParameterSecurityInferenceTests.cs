// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using Bicep.Core.Extensions;
using Bicep.Core.Syntax;
using Bicep.Core.TypeSystem;
using Bicep.Core.TypeSystem.Types;
using Bicep.Core.UnitTests.Assertions;
using Bicep.Core.UnitTests.Features;
using Bicep.Core.UnitTests.Utils;
using Bicep.Testing.Assertions.Json;
using FluentAssertions;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using static Bicep.Core.UnitTests.Utils.CompilationHelper;

namespace Bicep.Core.UnitTests.TypeSystem;

// The module parameter rules depend on type inference changes: keeping the item type when iterating a nullable
// or union array, typing the result of union(), reading properties of a discriminated object, and keeping
// @secure through interpolation and ternaries. They report new errors and warnings for existing programs, so
// they switch off together with the moduleParameterSecurity experimental feature.
[TestClass]
public class ModuleParameterSecurityInferenceTests
{
    private const string Preamble = """
        param items { name: string }[]?
        param left { x: string }
        param right { y: string }
        param lefts { x: string }[]
        param rights { y: string }[]
        @discriminator('kind')
        type shapeType = { kind: 'a', a: string } | { kind: 'b', b: string }
        param s shapeType
        """;

    [TestMethod]
    [DataRow("output result int[] = [for item in (items ?? []): item.name]", "BCP033", DisplayName = "loop over a nullable array")]
    [DataRow("output result int[] = map(items ?? [], item => item.name)", "BCP033", DisplayName = "map over a nullable array")]
    [DataRow("output result string[] = [for item in (items ?? []): item.nme]", "BCP187", DisplayName = "unknown property in a loop")]
    [DataRow("output result object = toObject(items ?? [], item => item.nme)", "BCP187", DisplayName = "unknown property in toObject")]
    [DataRow("output result object = toObject(items ?? [], item => 'key', item => item.nme)", "BCP187", DisplayName = "unknown property in the toObject value lambda")]
    [DataRow("output result object = groupBy(items ?? [], item => item.nme)", "BCP187", DisplayName = "unknown property in groupBy")]
    [DataRow("output result object = groupBy(items ?? [], item => 'key', item => item.nme)", "BCP187", DisplayName = "unknown property in the groupBy value lambda")]
    [DataRow("output result object[] = filter(items ?? [], item => item.name)", "BCP070", DisplayName = "non-boolean filter lambda")]
    [DataRow("output result object[] = sort(items ?? [], (a, b) => a.name)", "BCP070", DisplayName = "non-boolean sort lambda")]
    [DataRow("var all = concat(items ?? [], [{ name: 'x' }])\noutput result int = all[0].name", "BCP033", DisplayName = "concat of a nullable array")]
    [DataRow("var merged = union(left, right)\noutput result string = merged.z", "BCP053", DisplayName = "unknown property of a union of objects")]
    [DataRow("var merged = union(lefts, rights)\noutput result string = merged[0].z", "BCP187", DisplayName = "unknown property of a union of arrays")]
    [DataRow("output result string = s.c", "BCP187", DisplayName = "unknown property of a discriminated object")]
    [DataRow("output result string = s.a", "BCP187", DisplayName = "variant property of a discriminated object")]
    [DataRow("output result int = s.kind", "BCP033", DisplayName = "discriminator of a discriminated object")]
    public void Inference_changes_report_diagnostics_only_when_module_parameter_security_is_enabled(string body, string code)
    {
        var text = $"{Preamble}\n{body}";

        Compile(text, enabled: true).ExcludingLinterDiagnostics().Diagnostics.Select(diagnostic => diagnostic.Code).Distinct().Should().Equal(code);
        Compile(text, enabled: false).ExcludingLinterDiagnostics().Should().NotHaveAnyDiagnostics();
    }

    [TestMethod]
    public void Interpolating_a_secure_value_is_secure_only_when_module_parameter_security_is_enabled()
    {
        const string text = """
            @secure()
            param secret string
            param plain string
            var withSecret = 'prefix-${secret}'
            var withPlain = 'prefix-${plain}'
            """;

        GetVariableType(text, "withSecret", enabled: true).ValidationFlags.Should().HaveFlag(TypeSymbolValidationFlags.IsSecure);
        GetVariableType(text, "withSecret", enabled: false).ValidationFlags.Should().NotHaveFlag(TypeSymbolValidationFlags.IsSecure);
        GetVariableType(text, "withPlain", enabled: true).ValidationFlags.Should().NotHaveFlag(TypeSymbolValidationFlags.IsSecure);
    }

    [TestMethod]
    [DataRow("cond ? secret : 'public'", DisplayName = "secure and literal strings")]
    [DataRow("cond ? secureObject : plainObject", DisplayName = "secure and plain objects")]
    public void Ternary_keeps_secure_and_plain_branches_apart_only_when_module_parameter_security_is_enabled(string expression)
    {
        var text = $$"""
            @secure()
            param secret string
            @secure()
            param secureObject { a: string }
            param plainObject { a: string }
            param cond bool
            var result = {{expression}}
            """;

        GetVariableType(text, "result", enabled: true).Should().BeOfType<UnionType>();
        GetVariableType(text, "result", enabled: false).Should().NotBeOfType<UnionType>();
    }

    [TestMethod]
    public void Items_keeps_secure_and_plain_values_apart_only_when_module_parameter_security_is_enabled()
    {
        const string text = """
            @secure()
            param secret string
            var mixed = { a: secret, b: 'public' }
            var entries = items(mixed)
            """;

        GetItemsValueType(text, enabled: true).Should().BeOfType<AnyType>();
        GetItemsValueType(text, enabled: false).Should().NotBeOfType<AnyType>();

        static TypeSymbol GetItemsValueType(string text, bool enabled)
            => ((ObjectType)((ArrayType)GetVariableType(text, "entries", enabled)).Item.Type).Properties["value"].TypeReference.Type;
    }

    [TestMethod]
    public void Module_parameters_keep_a_secure_resource_derived_type_only_when_module_parameter_security_is_enabled()
    {
        const string parent = """
            module child 'child.json' = {
              name: 'child'
              params: {
                configurationProtectedSettings: {}
              }
            }
            """;
        const string child = """
            {
              "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
              "languageVersion": "2.0",
              "contentVersion": "1.0.0.0",
              "parameters": {
                "configurationProtectedSettings": {
                  "type": "secureObject",
                  "metadata": {
                    "__bicep_resource_derived_type!": {
                      "source": "Microsoft.KubernetesConfiguration/fluxConfigurations@2025-04-01#properties/properties/properties/configurationProtectedSettings"
                    }
                  }
                }
              },
              "resources": {}
            }
            """;

        GetModuleParameterType(enabled: true).ValidationFlags.Should().HaveFlag(TypeSymbolValidationFlags.IsSecure);
        GetModuleParameterType(enabled: false).ValidationFlags.Should().NotHaveFlag(TypeSymbolValidationFlags.IsSecure);

        static TypeSymbol GetModuleParameterType(bool enabled)
        {
            var model = CompilationHelper.Compile(Services(enabled), ("main.bicep", parent), ("child.json", child)).Compilation.GetEntrypointSemanticModel();
            var assignment = model.Root.ModuleDeclarations.Single().DeclaringModule.TryGetBody()?.TryGetPropertyByName("params")?.Value is ObjectSyntax parameters
                ? parameters.Properties.Single()
                : throw new AssertFailedException("Expected a module with a params object.");

            return model.GetDeclaredType(assignment) ?? throw new AssertFailedException("Expected a declared type for the module parameter.");
        }
    }

    // Everything the feature gates only changes what the type checker infers. It never changes what a program emits.
    [TestMethod]
    public void Emitted_templates_do_not_depend_on_module_parameter_security()
    {
        const string parent = """
            @secure()
            param secret string
            param cond bool
            param items { name: string }[]?
            param left { x: string }
            param right { y: string }
            param lefts { x: string }[]
            param rights { y: string }[]
            @discriminator('kind')
            type shapeType = { kind: 'a', a: string } | { kind: 'b', b: string }
            param s shapeType

            var interpolated = 'prefix-${secret}'
            var picked = cond ? secret : 'public'
            var names = [for item in (items ?? []): item.name]
            var mappedNames = map(items ?? [], item => item.name)
            var all = concat(items ?? [], [{ name: 'x' }])
            var merged = union(left, right)
            var mergedArrays = union(lefts, rights)

            module child 'child.bicep' = {
              name: 'child'
              params: {
                password: picked
                label: interpolated
                names: names
              }
            }

            output kind string = s.kind
            output allNames string[] = [for item in all: item.name]
            output count int = length(mappedNames)
            output x string = merged.x
            output y string? = mergedArrays[0].?x
            """;
        const string child = """
            @secure()
            param password string
            @secure()
            param label string
            param names string[]
            """;

        var enabled = CompilationHelper.Compile(Services(enabled: true), ("main.bicep", parent), ("child.bicep", child));
        var disabled = CompilationHelper.Compile(Services(enabled: false), ("main.bicep", parent), ("child.bicep", child));

        enabled.ExcludingLinterDiagnostics().Should().NotHaveAnyCompilationBlockingDiagnostics();
        disabled.ExcludingLinterDiagnostics().Should().NotHaveAnyCompilationBlockingDiagnostics();
        enabled.Template.Should().NotBeNull();
        enabled.Template.Should().DeepEqual(disabled.Template!);
    }

    private static ServiceBuilder Services(bool enabled)
        => new ServiceBuilder().WithFeatureOverrides(new FeatureProviderOverrides(ModuleParameterSecurityEnabled: enabled));

    private static CompilationResult Compile(string text, bool enabled)
        => CompilationHelper.Compile(Services(enabled), text);

    private static TypeSymbol GetVariableType(string text, string name, bool enabled)
    {
        var model = Compile(text, enabled).Compilation.GetEntrypointSemanticModel();

        return model.GetTypeInfo(model.Root.VariableDeclarations.Single(variable => variable.Name == name).DeclaringVariable.Value);
    }
}
