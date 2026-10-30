// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using Bicep.Core.Analyzers.Linter.Common;
using Bicep.Core.TypeSystem;
using Bicep.Core.TypeSystem.Types;
using FluentAssertions;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Bicep.Core.UnitTests.Analyzers.Linter.Common;

[TestClass]
public class SecureValueFlowTests
{
    [TestMethod]
    public void Secure_paths_keep_dotted_property_names_distinct()
    {
        var type = new ObjectType("paths", default,
        [
            new("a", new ObjectType("nested", default, [new("b", LanguageConstants.SecureString)])),
            new("a.b", LanguageConstants.SecureString),
        ]);

        SecureValueFlow.FindSecurePaths(type).Should().SatisfyRespectively(
            path => path.Should().Equal("a", "b"),
            path => path.Should().Equal("a.b"));
    }

    [TestMethod]
    public void Member_types_keep_secure_and_insecure_union_members_separate()
    {
        var type = TypeHelper.CreateTypeUnion(
            new ObjectType("secure", default, [new("value", LanguageConstants.SecureString)]),
            new ObjectType("insecure", default, [new("value", LanguageConstants.String)]),
            LanguageConstants.Null);

        SecureValueFlow.GetMemberType(type, "value").Should().BeOfType<UnionType>()
            .Which.Members.Select(member => member.Type).Should()
            .BeEquivalentTo([LanguageConstants.SecureString, LanguageConstants.String]);
    }

    [TestMethod]
    public void Member_types_accept_write_only_input_properties()
    {
        var type = new ObjectType("sink", default,
            [new("value", LanguageConstants.SecureString, TypePropertyFlags.WriteOnly)]);

        SecureValueFlow.GetMemberType(type, "value").Should().BeSameAs(LanguageConstants.SecureString);
    }
}
