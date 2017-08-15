using System;
using System.Collections.Generic;
using System.CommandLine;

namespace Get_AzureKeyVaultSecret
{
    class Program
    {
        static int Main(string[] args)
        {
            string adalClientId = null;
            string adalRedirectUri = null;
            string keyVaultAddress = null;
            bool nonInteractive = false;
            string secretName = null;

            ArgumentSyntax.Parse(args, syntax =>
            {
                var requiredOptions = new List<Argument>
                {
                    syntax.DefineOption("AdalClientId", ref adalClientId, true, "The Application ID for the app registered with the Azure Active Directory."),
                    syntax.DefineOption("AdalRedirectUri", ref adalRedirectUri, true, "A URI recorded for the AAD registered app as a valid redirect URI."),
                    syntax.DefineOption("KeyVaultAddress", ref keyVaultAddress, true, "For example: https://yourCoolApp.vault.azure.net/"),
                    syntax.DefineOption("NonInteractive", ref nonInteractive, true, "A value indicating whether the cmdlet should fail rather than prompt the user for credentials."),
                    syntax.DefineOption("SecretName", ref secretName, true, "The secret whose value should be retrieved."),
                };

                foreach (var option in requiredOptions)
                {
                    if (!option.IsSpecified)
                    {
                        syntax.ReportError($"{option.Name} is required.");
                    }
                }
            });

            var helper = new GetAzureKeyVaultSecret
            {
                ADALClientId = Guid.Parse(adalClientId),
                ADALRedirectUri = new Uri(adalRedirectUri, UriKind.Absolute),
                KeyVaultAddress = new Uri(keyVaultAddress, UriKind.Absolute),
                NonInteractive = nonInteractive,
                SecretName = secretName,
            };

            Console.WriteLine(helper.GetSecretAsync().GetAwaiter().GetResult());
            return 0;
        }
    }
}
