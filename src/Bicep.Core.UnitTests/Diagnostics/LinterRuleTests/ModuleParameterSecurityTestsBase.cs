// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using Bicep.Core.Analyzers.Linter.Rules;
using Bicep.Core.Diagnostics;
using Bicep.Core.UnitTests.Features;
using Bicep.Core.UnitTests.Utils;
using FluentAssertions;
using static Bicep.Core.UnitTests.Utils.CompilationHelper;

namespace Bicep.Core.UnitTests.Diagnostics.LinterRuleTests;

// Shared by the two rules that check values passed to module parameters. Both rules run on every
// compilation, so a test for one rule also shows what the other rule reports for the same module.
// The rules do nothing unless the moduleParameterSecurity experimental feature is enabled, so the
// helpers enable it by default and take `enabled: false` to check the off switch.
public abstract class ModuleParameterSecurityTestsBase : LinterRuleTestsBase
{
    protected static void AssertFlow(string parent, string child, int inputWarnings, int leakWarnings, string childPath = "child.bicep", bool enabled = true)
    {
        var result = CompileWithoutErrors(parent, child, childPath, enabled);
        GetWarnings(result, UseSecureValueForSecureInputsRule.Code).Should().HaveCount(inputWarnings);
        GetWarnings(result, NoSecureValuesInInsecureInputsRule.Code).Should().HaveCount(leakWarnings);
    }

    protected static void AssertFlow(string parent, string child, string[] inputWarnings, string[] leakWarnings, string childPath = "child.bicep", bool enabled = true)
    {
        var result = CompileWithoutErrors(parent, child, childPath, enabled);
        GetWarnings(result, UseSecureValueForSecureInputsRule.Code).Select(diagnostic => diagnostic.Message).Should().BeEquivalentTo(inputWarnings);
        GetWarnings(result, NoSecureValuesInInsecureInputsRule.Code).Select(diagnostic => diagnostic.Message).Should().BeEquivalentTo(leakWarnings);
    }

    // Replaces the `SECURE` marker in the parent with nothing, then with `@secure()`, and expects the child's
    // secure parameter to warn only in the first case.
    protected static void AssertHardening(string parent, string child, string input, string childPath = "child.bicep")
    {
        AssertFlow(parent.Replace("SECURE", ""), child, [InputWarning(input)], [], childPath);
        AssertFlow(parent.Replace("SECURE", "@secure()"), child, [], [], childPath);
    }

    protected static string InputWarning(string input)
        => $"Module parameter '{input}' expects a secure value, but the value provided may not be secure.";

    protected static string LeakWarning(string input)
        => $"Module parameter '{input}' is not secure, but is assigned a secure value. The value will be visible in the module deployment's inputs.";

    protected static CompilationResult CompileModule(string parent, string child, string childPath = "child.bicep", bool enabled = true)
    {
        var services = new ServiceBuilder().WithFeatureOverrides(new FeatureProviderOverrides(ModuleParameterSecurityEnabled: enabled));

        return CompilationHelper.Compile(services, ("main.bicep", parent), (childPath, child));
    }

    private static CompilationResult CompileWithoutErrors(string parent, string child, string childPath, bool enabled)
    {
        var result = CompileModule(parent, child, childPath, enabled);
        result.Diagnostics.Where(diagnostic => diagnostic.Level == DiagnosticLevel.Error).Should().BeEmpty();

        return result;
    }

    private static IDiagnostic[] GetWarnings(CompilationResult result, string code)
    {
        var diagnostics = result.Diagnostics.Where(diagnostic => diagnostic.Code == code).ToArray();
        diagnostics.Where(diagnostic => diagnostic.Level != DiagnosticLevel.Warning).Should().BeEmpty();

        return diagnostics;
    }
}
