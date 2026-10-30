// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using Bicep.Core.Analyzers.Linter.Rules;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Bicep.Core.UnitTests.Diagnostics.LinterRuleTests;

// Reduced from the before and after states of https://github.com/Azure/bicep-registry-modules/pull/7472.
// These retain forwarding expressions, not resource setup.
// Tests marked "Not in AVM" are synthetic edge cases around an AVM binding.
[TestClass]
public class ModuleParameterSecurityTests : LinterRuleTestsBase
{
    // api-management/service and api-management/service/workspace use the same subscription binding.
    [TestMethod]
    [DataRow("primaryKey", true, DisplayName = "api-management subscriptions primaryKey")]
    [DataRow("secondaryKey", true, DisplayName = "api-management subscriptions secondaryKey")]
    [DataRow("value", true, DisplayName = "api-management/service/workspace named values")]
    [DataRow("storageAccountAccessKey", true, DisplayName = "sql/server security alert policies")]
    [DataRow("contentType", true, DisplayName = "key-vault/vault secrets")]
    [DataRow("serviceUri", false, DisplayName = "container-registry/registry webhooks")]
    public void Hardening_forwarded_loop_members_removes_warning(string member, bool optional)
    {
        var nullable = optional ? "?" : "";
        var source = $$"""
type inputType = {
  SECURE
  {{member}}: string{{nullable}}
}
param inputs inputType[]?

module children 'child.bicep' = [for (item, index) in (inputs ?? []): {
  name: 'child-${index}'
  params: {
    {{member}}: item.{{nullable}}{{member}}
  }
}]
""";
        AssertHardening(source, $"@secure()\nparam {member} string{nullable}", member);
    }

    [TestMethod]
    public void Hardening_automation_variables_type_removes_warning()
    {
        const string forwarding = """

module children 'child.bicep' = [for (variable, index) in variables: {
  name: 'variable-${index}'
  params: {
    value: variable.value
  }
}]
""";
        const string child = "@secure()\nparam value string";
        AssertFlow("param variables array = []" + forwarding, child, [InputWarning("value")], []);
        AssertFlow("""
type variableType = {
  name: string
  @secure()
  value: string
  description: string?
  isEncrypted: bool?
}
param variables variableType[] = []
""" + forwarding, child, [], []);
    }

    // compute/virtual-machine and compute/virtual-machine-scale-set use the same DSC binding.
    [TestMethod]
    public void Hardening_dsc_config_type_removes_warning()
    {
        const string forwarding = """

module dsc 'child.bicep' = if (extensionDSCConfig.enabled) {
  name: 'dsc'
  params: {
    protectedSettings: extensionDSCConfig.?protectedSettings ?? {}
  }
}
""";
        const string child = "@secure()\nparam protectedSettings object?";
        AssertFlow("""
param extensionDSCConfig object = {
  enabled: false
}
""" + forwarding, child, [InputWarning("protectedSettings")], []);
        AssertFlow("""
type extensionDSCConfigType = {
  enabled: bool
  settings: object?
  @secure()
  protectedSettings: object?
}
param extensionDSCConfig extensionDSCConfigType = {
  enabled: false
}
""" + forwarding, child, [], []);
    }

    [TestMethod]
    public void Hardening_managed_environment_conditional_certificate_removes_warning()
        => AssertHardening("""
type certificateType = {
  SECURE
  certificateValue: string?
}
param certificate certificateType?

module managedEnvironment_certificate 'child.bicep' = if (!empty(certificate)) {
  name: 'certificate'
  params: {
    certificateValue: certificate.?certificateValue
  }
}
""", "@secure()\nparam certificateValue string?", "certificateValue");

    private const string CompiledFluxChild = """
{
  "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
  "languageVersion": "2.0",
  "contentVersion": "1.0.0.0",
  "parameters": {
    "configurationProtectedSettings": {
      "type": "secureObject",
      "nullable": true,
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

    [TestMethod]
    [DataRow(false, DisplayName = "container-service/managed-cluster to extension")]
    [DataRow(true, DisplayName = "kubernetes-configuration/extension to flux-configuration")]
    public void Compiled_resource_derived_secure_object_keeps_protection(bool loop)
    {
        var source = $$"""
type fluxType = {
  SECURE
  configurationProtectedSettings: resourceInput<'Microsoft.KubernetesConfiguration/fluxConfigurations@2025-04-01'>.properties.configurationProtectedSettings?
}
param fluxExtension fluxType
param fluxConfigurations fluxType[]?

module child 'child.json' = {{(loop ? "[for (fluxConfiguration, index) in (fluxConfigurations ?? []):" : "")}} {
  name: {{(loop ? "'flux-${index}'" : "'extension'")}}
  params: {
    configurationProtectedSettings: {{(loop ? "fluxConfiguration" : "fluxExtension")}}.?configurationProtectedSettings
  }
}{{(loop ? "]" : "")}}
""";
        AssertHardening(source, CompiledFluxChild, "configurationProtectedSettings", "child.json");
    }

    [TestMethod]
    public void Hardening_apim_named_value_fallback_removes_warning()
        => AssertHardening("""
SECURE
param newGuidValue string = newGuid()
type namedValueType = {
  @secure()
  value: string?
}
param namedValues namedValueType[]?

module children 'child.bicep' = [for (namedValue, index) in (namedValues ?? []): {
  name: 'named-value-${index}'
  params: {
    value: namedValue.?value ?? newGuidValue
  }
}]
""", "@secure()\nparam value string = newGuid()", "value");

    [TestMethod]
    public void Hardening_workspace_logger_credentials_removes_warning()
        => AssertHardening("""
type loggerType = {
  SECURE
  credentials: resourceInput<'Microsoft.ApiManagement/service/workspaces/loggers@2024-05-01'>.properties.credentials?
}
param loggers loggerType[]?

module children 'child.bicep' = [for (logger, index) in (loggers ?? []): {
  name: 'logger-${index}'
  params: {
    credentials: logger.?credentials
  }
}]
""", "@secure()\nparam credentials resourceInput<'Microsoft.ApiManagement/service/workspaces/loggers@2024-05-01'>.properties.credentials?", "credentials");

    // compute/virtual-machine and compute/virtual-machine-scale-set use the same custom script binding.
    [TestMethod]
    public void Custom_script_conditional_spreads_keep_secure_ancestor()
        => AssertFlow("""
type scriptType = {
  @secure()
  protectedSettings: {
    commandToExecute: string?
    storageAccountName: string?
    storageAccountKey: string?
    fileUris: string[]?
    managedIdentityResourceId: string?
  }?
}
param extensionCustomScriptConfig scriptType?

module script 'child.bicep' = {
  name: 'script'
  params: {
    protectedSettings: {
      ...(!empty(extensionCustomScriptConfig!.?protectedSettings.?commandToExecute)
        ? { commandToExecute: extensionCustomScriptConfig!.protectedSettings!.?commandToExecute }
        : {})
      ...(!empty(extensionCustomScriptConfig!.?protectedSettings.?storageAccountName)
        ? { storageAccountName: extensionCustomScriptConfig!.protectedSettings!.storageAccountName! }
        : {})
      ...(!empty(extensionCustomScriptConfig!.?protectedSettings.?storageAccountKey)
        ? { storageAccountKey: extensionCustomScriptConfig!.protectedSettings!.storageAccountKey! }
        : {})
      ...(!empty(extensionCustomScriptConfig!.?protectedSettings.?fileUris)
        ? { fileUris: extensionCustomScriptConfig!.protectedSettings!.fileUris! }
        : {})
      ...(extensionCustomScriptConfig!.?protectedSettings.?managedIdentityResourceId != null
        ? {
            managedIdentity: !empty(extensionCustomScriptConfig!.protectedSettings!.?managedIdentityResourceId)
              ? {
                  clientId: identity.properties.clientId
                }
              : {}
          }
        : {})
    }
  }
}
resource identity 'Microsoft.ManagedIdentity/userAssignedIdentities@2024-11-30' existing = {
  name: 'identity'
}
""", "@secure()\nparam protectedSettings object?", [], []);

    [TestMethod]
    public void Vmss_monitor_runtime_key_or_empty_string_is_not_an_insecure_caller_input()
        => AssertFlow("""
param monitoringWorkspaceResourceId string
resource workspace 'Microsoft.OperationalInsights/workspaces@2023-09-01' existing = {
  name: 'workspace'
}

module monitor 'child.bicep' = {
  name: 'monitor'
  params: {
    protectedSettings: {
      workspaceKey: !empty(monitoringWorkspaceResourceId) ? workspace.listKeys().primarySharedKey : ''
    }
  }
}
""", "@secure()\nparam protectedSettings object?", [], []);

    [TestMethod]
    public void Hardening_apim_cache_requires_securing_parent_and_child_together()
    {
        const string source = """
type cacheType = {
  SECURE
  connectionString: string
}
param caches cacheType[]?

module children 'child.bicep' = [for (cache, index) in (caches ?? []): {
  name: 'cache-${index}'
  params: {
    connectionString: cache.connectionString
  }
}]
""";
        AssertFlow(source.Replace("SECURE", ""), "param connectionString string", [], []);
        AssertFlow(source.Replace("SECURE", "@secure()"), "@secure()\nparam connectionString string", [], []);
        AssertFlow(source.Replace("SECURE", ""), "@secure()\nparam connectionString string", [InputWarning("connectionString")], []);
    }

    // Not in AVM: a resource-derived dictionary forwarded on its own.
    [TestMethod]
    public void Flux_resource_derived_dictionary_alone_has_no_sensitivity_to_infer()
        => AssertFlow("""
param settings resourceInput<'Microsoft.KubernetesConfiguration/fluxConfigurations@2025-04-01'>.properties.configurationProtectedSettings?

module child 'child.bicep' = {
  name: 'child'
  params: {
    settings: settings
  }
}
""", "param settings object?", [], []);

    private static void AssertHardening(string source, string child, string input, string childPath = "child.bicep")
    {
        AssertFlow(source.Replace("SECURE", ""), child, [InputWarning(input)], [], childPath);
        AssertFlow(source.Replace("SECURE", "@secure()"), child, [], [], childPath);
    }

    private static void AssertFlow(string source, string child, string[] inputWarnings, string[] leakWarnings, string childPath = "child.bicep")
    {
        var options = new Options(IncludePosition: IncludePosition.None, AdditionalFiles: [(childPath, child)]);
        AssertLinterRuleDiagnostics(UseSecureValueForSecureInputsRule.Code, source, inputWarnings, options);
    }

    private static string InputWarning(string input)
        => $"Property '{input}' expects a secure value, but the value provided may not be secure.";
}
