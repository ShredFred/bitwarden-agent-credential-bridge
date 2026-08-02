using System;
using System.Text;

namespace BitwardenAgentCredentialBridgeHelper;

internal static class AuthorizeSchemaProbe
{
    private const int MaxRequestBytes = 64 * 1024;
    private static readonly byte[] DeniedResponse = Encoding.ASCII.GetBytes(
        "{\"schema_version\":1,\"request_schema_valid\":true,\"operation_recognized\":true," +
        "\"different_principal_required\":true,\"target_acl_evidence_complete\":false," +
        "\"manifest_executor_absent\":true,\"vault_client_absent\":true," +
        "\"network_stack_absent\":true,\"mutation_authorized\":false," +
        "\"authorization_denied\":true}\n"
    );
    private static readonly byte[] InvalidResponse = Encoding.ASCII.GetBytes(
        "{\"schema_version\":1,\"request_schema_valid\":false,\"operation_recognized\":false," +
        "\"different_principal_required\":true,\"target_acl_evidence_complete\":false," +
        "\"manifest_executor_absent\":true,\"vault_client_absent\":true," +
        "\"network_stack_absent\":true,\"mutation_authorized\":false," +
        "\"authorization_denied\":true}\n"
    );

    internal static int RunSelfTestFromStdin()
    {
        if (!Console.IsInputRedirected)
        {
            Console.Out.Write(Encoding.ASCII.GetString(InvalidResponse));
            return 41;
        }
        string raw = Console.In.ReadToEnd();
        if (string.IsNullOrEmpty(raw) || Encoding.UTF8.GetByteCount(raw) > MaxRequestBytes)
        {
            Console.Out.Write(Encoding.ASCII.GetString(InvalidResponse));
            return 41;
        }
        bool valid = LooksLikeAuthorizeRequest(raw);
        Console.Out.Write(Encoding.ASCII.GetString(valid ? DeniedResponse : InvalidResponse));
        return valid ? 0 : 42;
    }

    internal static bool LooksLikeAuthorizeRequest(string raw)
    {
        string trimmed = raw.Trim();
        return trimmed.StartsWith('{') &&
            trimmed.Contains("\"protocol_version\":1") &&
            trimmed.Contains("\"operation\":\"apply_disposable_manifest\"") &&
            trimmed.Contains("\"manifest_digest\"") &&
            trimmed.Contains("\"launcher\"");
    }
}
