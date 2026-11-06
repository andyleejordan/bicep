// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using Bicep.Core.Diagnostics;
using Bicep.Core.Extensions;
using Bicep.Core.Syntax;
using Bicep.Core.TypeSystem.Types;
using Bicep.Core.UnitTests;
using Bicep.Core.UnitTests.Assertions;
using Bicep.Core.UnitTests.Utils;
using FluentAssertions;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Bicep.Core.IntegrationTests.Scenarios;

[TestClass]
public class DeadBranchTests
{
    [TestMethod]
    [DataRow("false", "cfg.a", "'default'")]
    [DataRow("true", "'default'", "cfg.a")]
    [DataRow("!true", "cfg.a", "'default'")]
    [DataRow("1 == 1", "'default'", "cfg.a")]
    public void Literal_typed_conditions_ignore_errors_in_the_dead_branch(string condition, string trueExpression, string falseExpression)
    {
        var result = CompilationHelper.Compile($$"""
            var flag = {{condition}}
            var cfg = {}
            var value = flag ? {{trueExpression}} : {{falseExpression}}
            output value string = value
            """);

        result.ExcludingLinterDiagnostics().Should().NotHaveAnyDiagnostics();
        result.Template.Should().NotBeNull();
        result.Compilation.GetEntrypointSemanticModel()
            .GetTypeInfo(result.BicepFile.ProgramSyntax.Children.OfType<VariableDeclarationSyntax>().Last().Value)
            .Should().BeOfType<StringLiteralType>().Which.RawStringValue.Should().Be("default");
    }

    [TestMethod]
    public void Cyclecloud_conditional_union_remains_valid()
    {
        var result = CompilationHelper.Compile("""
            param createLustre bool
            var createDatabase = false
            func cfg(ip string) object => {
              cyclecloud: { cidr: 29 }
              database: { cidr: 28 }
            }
            var subnetCidr = cfg('10.0.0.0/24')
            var vnet = {
              subnets: union(
                { cyclecloud: { name: 'a', cidr: subnetCidr.cyclecloud } },
                createLustre ? { lustre: { name: 'b', cidr: subnetCidr.lustre } } : {},
                createDatabase ? { database: { name: 'c', cidr: subnetCidr.database } } : {}
              )
            }
            var databaseId = createDatabase ? vnet.subnets.database.name : ''
            output databaseId string = databaseId
            """);

        result.ExcludingLinterDiagnostics().Should().NotHaveAnyDiagnostics();
        result.Template.Should().NotBeNull();
    }

    [TestMethod]
    public void Nested_dead_branches_do_not_propagate_errors()
    {
        var result = CompilationHelper.Compile("""
            var flag = false
            var cfg = flag ? { a: 'x' } : {}
            var value = flag ? (cfg.a ? cfg.b : cfg.c) : 'default'
            output value string = value
            """);

        result.ExcludingLinterDiagnostics().Should().NotHaveAnyDiagnostics();
        result.Template.Should().NotBeNull();
    }

    [TestMethod]
    [DataRow("var flag = true")]
    [DataRow("param flag bool")]
    [DataRow("param flag bool = false")]
    [DataRow("var flag bool = false")]
    public void Live_or_unknown_branches_still_report_type_errors(string declaration)
    {
        var result = CompilationHelper.Compile($$"""
            {{declaration}}
            var cfg = {}
            output value string = flag ? cfg.a : 'default'
            """);

        result.Diagnostics.Should().Contain(x => x.Code == "BCP052" && x.Level == DiagnosticLevel.Error);
        result.Template.Should().BeNull();
    }

    [TestMethod]
    public void Referenced_declarations_are_checked_even_when_the_reference_is_dead()
    {
        var result = CompilationHelper.Compile("""
            var invalid = {}.a
            output value string = false ? invalid : 'default'
            """);

        result.Diagnostics.Should().Contain(x => x.Code == "BCP052" && x.Level == DiagnosticLevel.Error);
        result.Template.Should().BeNull();
    }

    [TestMethod]
    [DataRow("false ? missingName : 'default'", "BCP057")]
    [DataRow("false ? missingFunction() : 'default'", "BCP057")]
    [DataRow("false ? newGuid() : 'default'", "BCP065")]
    [DataRow("false ? string : 'default'", "BCP288")]
    [DataRow("false ? (x => x) : 'default'", "BCP242")]
    [DataRow("false ? ('unclosed' : 'default'", "BCP018")]
    [DataRow("123 ? 'unused' : 'default'", "BCP046")]
    public void Syntax_binding_and_condition_errors_remain(string expression, string diagnosticCode)
    {
        var result = CompilationHelper.Compile($"output value string = {expression}");

        result.Diagnostics.Should().Contain(x => x.Code == diagnosticCode && x.Level == DiagnosticLevel.Error);
        result.Template.Should().BeNull();
    }

    [TestMethod]
    public void Cycles_remain_errors_even_when_the_reference_is_dead()
    {
        var result = CompilationHelper.Compile("""
            var value = false ? value : 'default'
            output result string = value
            """);

        result.Diagnostics.Should().Contain(x => x.Code == "BCP079" && x.Level == DiagnosticLevel.Error);
        result.Template.Should().BeNull();
    }

    [TestMethod]
    [DataRow("123", false)]
    [DataRow("input", true)]
    public void Hover_type_requests_do_not_reintroduce_dead_branch_diagnostics(string argument, bool nullableArgument)
    {
        var services = new ServiceBuilder();
        var compiler = services.Build().GetCompiler();
        var fileUri = new Uri("file:///main.bicep");
        var compilation = compiler.CreateCompilationWithoutRestore(fileUri.ToIOUri(),
            CompilationHelper.CreateWorkspace(compiler.SourceFileFactory, new Dictionary<Uri, string>
            {
                [fileUri] = $$"""
                    param input string?
                    var flag = false
                    var cfg = {}
                    output value string = flag ? toLower({{argument}}) : 'default'
                    """,
            }));
        var model = compilation.GetEntrypointSemanticModel();
        var output = model.SourceFile.ProgramSyntax.Children.OfType<OutputDeclarationSyntax>().Single();
        var ternary = (TernaryOperationSyntax)output.Value;

        var branchType = model.GetTypeInfo(ternary.TrueExpression);
        if (nullableArgument)
        {
            branchType.Should().NotBeOfType<ErrorType>();
        }
        else
        {
            branchType.Should().BeOfType<ErrorType>();
        }
        model.GetTypeInfo(ternary).Should().BeOfType<StringLiteralType>();
        model.GetAllDiagnostics().Should().NotContain(x => x.Level == DiagnosticLevel.Error || x.Code == "BCP321");
        CompilationHelper.GetCompilationResult(compilation).Template.Should().NotBeNull();
    }
}
