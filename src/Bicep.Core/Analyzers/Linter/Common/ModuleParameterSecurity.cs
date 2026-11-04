// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using Bicep.Core.Diagnostics;
using Bicep.Core.Extensions;
using Bicep.Core.Semantics;
using Bicep.Core.Syntax;
using Bicep.Core.TypeSystem;
using Bicep.Core.TypeSystem.Providers;
using Bicep.Core.TypeSystem.Types;

namespace Bicep.Core.Analyzers.Linter.Common;

public static class ModuleParameterSecurity
{
    /// <summary>
    /// Enumerates the parameter assignments of every module declaration. Yields nothing unless the
    /// moduleParameterSecurity experimental feature is enabled.
    /// </summary>
    public static IEnumerable<ObjectPropertySyntax> EnumerateAssignments(SemanticModel model)
        => model.Features.ModuleParameterSecurityEnabled
            ? model.Root.ModuleDeclarations
                .SelectMany(module => module.DeclaringModule.TryGetBody()
                    ?.TryGetPropertyByName(LanguageConstants.ModuleParamsPropertyName)?.Value is ObjectSyntax parameters
                        ? parameters.Properties
                        : [])
            : [];

    public static IEnumerable<string> EnumerateMismatches(SemanticModel model, ObjectPropertySyntax assignment, bool secureInput)
    {
        if (model.GetDeclaredType(assignment) is not { } target || assignment.TryGetKeyText() is not { } name)
        {
            return [];
        }

        var resolver = secureInput ? ResourceTypeResolver.Create(model) : null;
        return CheckExpression(assignment.Value, target, name).Distinct();

        IEnumerable<string> CheckExpression(SyntaxBase value, TypeSymbol target, string path)
        {
            if (model.GetTypeInfo(value) is ErrorType ||
                value is FunctionCallSyntaxBase && model.GetSymbolInfo(value) is FunctionSymbol function &&
                function.FunctionFlags.HasFlag(FunctionFlags.ModuleSecureParameterOnly))
            {
                yield break;
            }

            switch (value)
            {
                case ParenthesizedExpressionSyntax parenthesized:
                    foreach (var mismatch in CheckExpression(parenthesized.Expression, target, path))
                    {
                        yield return mismatch;
                    }
                    yield break;
                case NonNullAssertionSyntax nonNull:
                    foreach (var mismatch in CheckExpression(nonNull.BaseExpression, target, path))
                    {
                        yield return mismatch;
                    }
                    yield break;
                case VariableAccessSyntax access when model.GetSymbolInfo(access) is VariableSymbol variable:
                    foreach (var mismatch in CheckExpression(variable.DeclaringVariable.Value, target, path))
                    {
                        yield return mismatch;
                    }
                    yield break;
                case TernaryOperationSyntax ternary:
                    foreach (var mismatch in CheckExpression(ternary.TrueExpression, target, path)
                        .Concat(CheckExpression(ternary.FalseExpression, target, path)))
                    {
                        yield return mismatch;
                    }
                    yield break;
                case BinaryOperationSyntax { Operator: BinaryOperator.Coalesce } coalesce:
                    foreach (var mismatch in CheckExpression(coalesce.LeftExpression, target, path)
                        .Concat(CheckExpression(coalesce.RightExpression, target, path)))
                    {
                        yield return mismatch;
                    }
                    yield break;
                case ObjectSyntax obj when Variants(target) is { } variants:
                    foreach (var mismatch in variants.Where(variant => MayMatch(model.GetTypeInfo(obj), variant))
                        .SelectMany(variant => CheckExpression(obj, variant, path)))
                    {
                        yield return mismatch;
                    }
                    yield break;
                case ObjectSyntax obj when !obj.Children.OfType<SpreadExpressionSyntax>().Any():
                    foreach (var property in obj.Properties)
                    {
                        var name = property.TryGetKeyText();
                        foreach (var mismatch in CheckExpression(property.Value, Member(target, name), $"{path}.{name ?? "*"}"))
                        {
                            yield return mismatch;
                        }
                    }
                    yield break;
                case ArraySyntax array when !array.Children.OfType<SpreadExpressionSyntax>().Any():
                    foreach (var (index, item) in array.Items.Select((item, index) => (index, item)))
                    {
                        foreach (var mismatch in CheckExpression(item.Value, Item(target, index), $"{path}[{index}]"))
                        {
                            yield return mismatch;
                        }
                    }
                    yield break;
                case ForSyntax loop:
                    foreach (var mismatch in CheckExpression(loop.Body, Item(target), $"{path}[*]"))
                    {
                        yield return mismatch;
                    }
                    yield break;
            }

            if (resolver is not null)
            {
                var diagnostics = ToListDiagnosticWriter.Create();
                DeployTimeConstantValidator.CheckDeployTimeConstantViolations(assignment, value, model, diagnostics, resolver);
                if (diagnostics.GetDiagnostics().Count > 0)
                {
                    yield break;
                }
            }

            // The secret visitor excludes getSecret(), whose use inside interpolation already produces BCP180.
            var source = value is StringSyntax { Expressions.Length: > 0 } ? LanguageConstants.String : model.GetTypeInfo(value);
            var sourceSecure = FindPossibleSecretsVisitor.FindPossibleSecretsInExpression(model, value).Any(secret =>
                source is StringType or IntegerType or BooleanType or AnyType ||
                ReferenceEquals(secret.Syntax, value) ||
                value is AccessExpressionSyntax && !TypeHelper.IsOrContainsSecureType(source));

            foreach (var mismatch in Compare(source, target, path, sourceSecure, false, []))
            {
                yield return mismatch;
            }
        }

        IEnumerable<string> Compare(TypeSymbol source, TypeSymbol target, string path, bool sourceSecure, bool targetSecure,
            HashSet<(TypeSymbol, TypeSymbol, bool, bool)> visiting)
        {
            if (source is NullType or ErrorType or StringLiteralType { RawStringValue: "" } || source.TypeKind == TypeKind.Never ||
                target is NullType or ErrorType ||
                !visiting.Add((source, target, sourceSecure, targetSecure)))
            {
                yield break;
            }

            var pair = (source, target, sourceSecure, targetSecure);
            try
            {
                sourceSecure |= source.ValidationFlags.HasFlag(TypeSymbolValidationFlags.IsSecure);
                targetSecure |= target.ValidationFlags.HasFlag(TypeSymbolValidationFlags.IsSecure);

                if (Variants(source) is { } sources)
                {
                    foreach (var mismatch in sources.SelectMany(member => Compare(member, target, path, sourceSecure, targetSecure, visiting)))
                    {
                        yield return mismatch;
                    }
                }
                else if (Variants(target) is { } targets)
                {
                    foreach (var mismatch in targets.Where(member => MayMatch(source, member))
                        .SelectMany(member => Compare(source, member, path, sourceSecure, targetSecure, visiting)))
                    {
                        yield return mismatch;
                    }
                }
                else if (sourceSecure)
                {
                    if (!secureInput && !targetSecure)
                    {
                        yield return path;
                    }
                }
                else if (!secureInput && targetSecure)
                {
                    yield break;
                }
                else if (source is TupleType tuple)
                {
                    foreach (var (index, item) in tuple.Items.Select((item, index) => (index, item)))
                    {
                        foreach (var mismatch in Compare(item.Type, Item(target, index), $"{path}[{index}]",
                            sourceSecure, targetSecure, visiting))
                        {
                            yield return mismatch;
                        }
                    }
                }
                else if (source is ArrayType sourceArray)
                {
                    foreach (var mismatch in Compare(sourceArray.Item.Type, Item(target), $"{path}[*]",
                        sourceSecure, targetSecure, visiting))
                    {
                        yield return mismatch;
                    }
                }
                else if (target is ArrayType targetArray)
                {
                    foreach (var mismatch in Compare(source, targetArray.Item.Type, $"{path}[*]", sourceSecure, targetSecure, visiting))
                    {
                        yield return mismatch;
                    }
                }
                else if (source is ObjectType || target is ObjectType)
                {
                    IEnumerable<string> sourceProperties = (source as ObjectType)?.Properties.Keys ?? [];
                    IEnumerable<string> targetProperties = (target as ObjectType)?.Properties.Keys ?? [];
                    foreach (var property in sourceProperties.Union(targetProperties))
                    {
                        foreach (var mismatch in Compare(Member(source, property), Member(target, property), $"{path}.{property}",
                            sourceSecure, targetSecure, visiting))
                        {
                            yield return mismatch;
                        }
                    }

                    if (source is ObjectType { HasExplicitAdditionalPropertiesType: true, AdditionalProperties: { } additional })
                    {
                        foreach (var mismatch in Compare(additional.TypeReference.Type,
                            Member(target, null), $"{path}.*", sourceSecure, targetSecure, visiting))
                        {
                            yield return mismatch;
                        }
                    }
                    else if (source is not ObjectType && secureInput && targetSecure)
                    {
                        yield return path;
                    }
                }
                else if (secureInput && targetSecure)
                {
                    yield return path;
                }
            }
            finally
            {
                visiting.Remove(pair);
            }
        }
    }

    private static IEnumerable<TypeSymbol>? Variants(TypeSymbol type) => type switch
    {
        UnionType union => union.Members.Select(member => member.Type),
        DiscriminatedObjectType discriminated => discriminated.UnionMembersByKey.Values,
        _ => null,
    };

    private static bool MayMatch(TypeSymbol source, TypeSymbol target)
        => TypeValidator.AreTypesAssignable(source, target) &&
            (source is not ObjectType sourceObject || target is not ObjectType targetObject ||
                targetObject.Properties.Values.All(property =>
                    !sourceObject.Properties.TryGetValue(property.Name, out var supplied) ||
                    TypeValidator.AreTypesAssignable(supplied.TypeReference.Type, property.TypeReference.Type)));

    private static TypeSymbol Member(TypeSymbol type, string? name) => type switch
    {
        _ when type.ValidationFlags.HasFlag(TypeSymbolValidationFlags.IsSecure) => type,
        UnionType union => TypeHelper.CreateTypeUnion(union.Members.Where(member => member.Type is not NullType).Select(member => Member(member.Type, name))),
        DiscriminatedObjectType discriminated => TypeHelper.CreateTypeUnion(discriminated.UnionMembersByKey.Values.Select(member => Member(member, name))),
        ObjectType obj when name is not null && obj.Properties.TryGetValue(name, out var property) => property.TypeReference.Type,
        ObjectType { HasExplicitAdditionalPropertiesType: true, AdditionalProperties: { } additional } => additional.TypeReference.Type,
        ObjectType => LanguageConstants.Never,
        _ => LanguageConstants.Any,
    };

    private static TypeSymbol Item(TypeSymbol type, int? index = null) => type switch
    {
        _ when type.ValidationFlags.HasFlag(TypeSymbolValidationFlags.IsSecure) => type,
        TupleType tuple when index is { } i && i < tuple.Items.Length => tuple.Items[i].Type,
        _ => TypeHelper.GetArrayItemType(type),
    };
}
